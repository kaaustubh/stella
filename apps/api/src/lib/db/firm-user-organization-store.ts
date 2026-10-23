import { generateId } from "@better-auth/core/utils/id";
import { Result } from "better-result";
import { eq } from "drizzle-orm";

import { member, organization } from "@/api/db/auth-schema";
import type { Transaction } from "@/api/db/root";
import { seedDefaultSkills } from "@/api/lib/agent-skills/default-skills";
import {
  AUDIT_ACTION,
  AUDIT_RESOURCE_TYPE,
  createBackgroundAuditRecorder,
} from "@/api/lib/audit-log";
import type { SafeId } from "@/api/lib/branded-types";
import { withAggregateTransaction } from "@/api/lib/db/aggregate-lock";
import type { MemberRole } from "@/api/lib/member-roles";
import { checkMemberAdmission } from "@/api/lib/usage/member-capacity";

// Better Auth's default id length, the shape every auth row holds.
const AUTH_ID_LENGTH = 32;

type OwnerDatabase = Pick<Transaction, "select" | "transaction">;

type FirmMembership = {
  organizationId: SafeId<"organization">;
  userId: SafeId<"user">;
  role: Exclude<MemberRole, "owner">;
};

const provisioningAuditBindings = ({
  organizationId,
  userId,
}: FirmMembership) => ({
  execution: {
    performer: {
      type: "service" as const,
      id: "firm-user-provisioning",
      name: "Firm user provisioning",
    },
    trigger: {
      type: "system" as const,
      source: "firm_user_provisioning",
    },
  },
  organizationId,
  userId,
  workspaceId: null,
});

/**
 * The organization half of operator-provisioned firm users, for self-hosted
 * instances that cannot deliver invitation email. A direct insert skips the
 * organization plugin's membership hooks, so the capacity check and member
 * defaults those hooks apply run here, with an audit event. The connection
 * owner binds this to the owner connection (`db/root.ts`).
 */
export const createFirmUserOrganizationStore = (db: OwnerDatabase) => ({
  listOrganizationIds: async () =>
    (await db.select({ id: organization.id }).from(organization)).map(
      (row) => row.id,
    ),
  hasMembership: async (userId: SafeId<"user">) =>
    (
      await db
        .select({ id: member.id })
        .from(member)
        .where(eq(member.userId, userId))
        .limit(1)
    ).length > 0,
  checkAdmission: async (organizationId: SafeId<"organization">) =>
    await checkMemberAdmission(db, { organizationId, kind: "membership" }),
  addMember: async (membership: FirmMembership) =>
    await withAggregateTransaction(db, async (tx) => {
      const { organizationId, userId, role } = membership;
      const admission = await checkMemberAdmission(tx, {
        organizationId,
        kind: "membership",
      });
      if (admission.isErr()) {
        return admission;
      }
      await tx.insert(member).values({
        id: generateId(AUTH_ID_LENGTH),
        organizationId,
        userId,
        role,
        createdAt: new Date(),
      });
      await seedDefaultSkills({ organizationId, tx, userId });
      await createBackgroundAuditRecorder(
        provisioningAuditBindings(membership),
      )(tx, {
        action: AUDIT_ACTION.CREATE,
        resourceType: AUDIT_RESOURCE_TYPE.ORGANIZATION_SETTINGS,
        resourceId: organizationId,
        metadata: { cause: "firm_user_member_added", role },
      });
      return Result.ok(undefined);
    }),
});
