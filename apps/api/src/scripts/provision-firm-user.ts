/**
 * Usage (inside the API container; the password is read from standard input):
 *   bun /app/provision-firm-user.js add <email> <role> <name...>
 *   bun /app/provision-firm-user.js set-password <email>
 *
 * For self-hosted instances that cannot deliver invitation email. `add`
 * creates a verified account with a password and joins it to the instance's
 * only organization as admin, member, intern or external. `set-password`
 * replaces an account's password and ends its browser sessions. Only fixed
 * outcome words are printed; the password never appears in arguments, the
 * environment or output.
 */
import { Result, TaggedError } from "better-result";

import { printError } from "@stll/errors";
import { runScriptWithErrorOutput } from "@stll/errors/script-error";

import { bindOwnerFirmUserOrganizationStore } from "@/api/db/root";
import { getAuth } from "@/api/lib/auth";
import { createFirmUserOrganizationStore } from "@/api/lib/db/firm-user-organization-store";
import { isMemberRole } from "@/api/lib/member-roles";
import type { MemberRole } from "@/api/lib/member-roles";
import {
  brandPersistedOrganizationId,
  brandPersistedUserId,
} from "@/api/lib/safe-id-boundaries";

// Matches the self-host password policy (`password-sign-in-options.ts`).
const PASSWORD_MIN_LENGTH = 12;
/** Better Auth's own maximum; a longer password could never sign in. */
const PASSWORD_MAX_LENGTH = 128;
const STDIN_MAX_BYTES = 4096;

const COMMAND = {
  add: "add",
  setPassword: "set-password",
} as const;

class FirmUserCommandError extends TaggedError("FirmUserCommandError")<{
  code:
    | "usage"
    | "invalid-role"
    | "password-too-short"
    | "password-too-long"
    | "password-unreadable"
    | "account-exists"
    | "account-missing"
    | "organization-not-unique"
    | "member-capacity-reached";
  message: string;
}> {}

type FirmRole = Exclude<MemberRole, "owner">;

const isFirmRole = (role: string): role is FirmRole =>
  isMemberRole(role) && role !== "owner";

const readPassword = async (): Promise<
  Result<string, FirmUserCommandError>
> => {
  const raw = await Bun.stdin.text();
  if (raw.length > STDIN_MAX_BYTES) {
    return Result.err(
      new FirmUserCommandError({
        code: "password-unreadable",
        message: "Standard input is longer than one password line.",
      }),
    );
  }
  const password = raw.replace(/\r?\n$/u, "");
  if (password.length < PASSWORD_MIN_LENGTH) {
    return Result.err(
      new FirmUserCommandError({
        code: "password-too-short",
        message: `The password needs at least ${PASSWORD_MIN_LENGTH} characters.`,
      }),
    );
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return Result.err(
      new FirmUserCommandError({
        code: "password-too-long",
        message: `The password allows at most ${PASSWORD_MAX_LENGTH} characters.`,
      }),
    );
  }
  return Result.ok(password);
};

const organizations = bindOwnerFirmUserOrganizationStore(
  createFirmUserOrganizationStore,
);

const findSoleOrganizationId = async () => {
  const ids = await organizations.listOrganizationIds();
  const id = ids.at(0);
  if (ids.length !== 1 || id === undefined) {
    return Result.err(
      new FirmUserCommandError({
        code: "organization-not-unique",
        message: `Expected exactly one organization, found ${ids.length}.`,
      }),
    );
  }
  return Result.ok(brandPersistedOrganizationId(id));
};

type AuthContext = Awaited<ReturnType<typeof getAuth>["$context"]>;

/** Hashes the password and links or replaces the account's credential. */
const storePassword = async (
  context: AuthContext,
  { userId, password }: { userId: string; password: string },
) => {
  const hash = await context.password.hash(password);
  const accounts = await context.internalAdapter.findAccounts(userId);
  const hasCredential = accounts.some(
    (account) =>
      account.providerId === "credential" && account.accountId === userId,
  );
  if (hasCredential) {
    await context.internalAdapter.updatePassword(userId, hash);
    return;
  }
  await context.internalAdapter.linkAccount({
    userId,
    providerId: "credential",
    accountId: userId,
    password: hash,
  });
};

type AddOptions = { email: string; role: string; name: string };

const addFirmUser = async ({ email, role, name }: AddOptions) => {
  if (!isFirmRole(role)) {
    return Result.err(
      new FirmUserCommandError({
        code: "invalid-role",
        message: "Role must be admin, member, intern or external.",
      }),
    );
  }
  const password = await readPassword();
  if (password.isErr()) {
    return password;
  }
  const auth = getAuth();
  const context = await auth.$context;
  // An account without a membership (left by an interrupted run) is adopted;
  // one that already belongs to an organization is refused.
  const existing = await context.internalAdapter.findUserByEmail(email);
  if (
    existing &&
    (await organizations.hasMembership(brandPersistedUserId(existing.user.id)))
  ) {
    return Result.err(
      new FirmUserCommandError({
        code: "account-exists",
        message:
          "An account with this email already belongs to an organization.",
      }),
    );
  }
  const organizationId = await findSoleOrganizationId();
  if (organizationId.isErr()) {
    return organizationId;
  }
  // Checked before the account exists so a full organization leaves no
  // orphaned account; the membership insert checks again in its transaction.
  const admission = await organizations.checkAdmission(organizationId.value);
  if (admission.isErr()) {
    return Result.err(
      new FirmUserCommandError({
        code: "member-capacity-reached",
        message: admission.error.message,
      }),
    );
  }
  // The server-only provisioning endpoint is an allowed account-creation
  // path, so Better Auth's user hooks run. Self-host password sign-in does
  // not require verification; the address is marked verified because the
  // operator vouches for it.
  const userId = brandPersistedUserId(
    existing
      ? existing.user.id
      : (
          await auth.api.createAgentUser({
            body: { email, name, emailVerified: true },
          })
        ).id,
  );
  await storePassword(context, { userId, password: password.value });
  const membership = await organizations.addMember({
    organizationId: organizationId.value,
    userId,
    role,
  });
  if (membership.isErr()) {
    return Result.err(
      new FirmUserCommandError({
        code: "member-capacity-reached",
        message: membership.error.message,
      }),
    );
  }
  return Result.ok(existing ? `adopted ${role}` : `created ${role}`);
};

const setFirmUserPassword = async (email: string) => {
  const password = await readPassword();
  if (password.isErr()) {
    return password;
  }
  const context = await getAuth().$context;
  const found = await context.internalAdapter.findUserByEmail(email);
  if (!found) {
    return Result.err(
      new FirmUserCommandError({
        code: "account-missing",
        message: "No account has this email.",
      }),
    );
  }
  const userId = found.user.id;
  await storePassword(context, { userId, password: password.value });
  const sessions = await context.internalAdapter.listSessions(userId);
  await context.internalAdapter.deleteUserSessions(userId);
  return Result.ok(`password-set sessions-ended ${sessions.length}`);
};

const runCommand = async (argv: string[]) => {
  const [command, rawEmail, ...rest] = argv;
  const email = rawEmail?.trim().toLowerCase();
  if (command === COMMAND.add && email && rest.length >= 2) {
    const [role, ...nameParts] = rest;
    return await addFirmUser({
      email,
      role: role ?? "",
      name: nameParts.join(" "),
    });
  }
  if (command === COMMAND.setPassword && email && rest.length === 0) {
    return await setFirmUserPassword(email);
  }
  return Result.err(
    new FirmUserCommandError({
      code: "usage",
      message:
        "Usage: add <email> <role> <name...> | set-password <email> (password on standard input)",
    }),
  );
};

await runScriptWithErrorOutput(async () => {
  const outcome = await runCommand(process.argv.slice(2));
  if (outcome.isErr()) {
    printError(outcome.error);
    process.exit(1);
  }
  process.stdout.write(`${outcome.value}\n`);
  process.exit(0);
});
