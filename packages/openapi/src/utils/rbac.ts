import {
  PERMISSION_ACTIONS,
  PERMISSION_SCOPE,
  type PermissionScope,
  RBAC_PERMISSIONS,
  type RBAC_PERMISSIONS_KEY,
} from '@/const/rbac';

/**
 * Generate permission codes with specified scopes for a given permission action key.
 * @param permissionKey - The permission action key (e.g., 'AGENT_READ', 'FILE_UPLOAD')
 * @param scopes - Array of scopes to generate permissions for (default: ['ALL', 'OWNER'])
 * @returns Array of permission codes with the specified scopes
 *
 * @example
 * // Generate ALL scope permission for AGENT_READ
 * getScopePermissions('AGENT_READ', ['ALL'])
 * // Returns: ['agent:read:all']
 *
 * @example
 * // Generate both ALL and OWNER scope permissions
 * getScopePermissions('FILE_UPLOAD', ['ALL', 'OWNER'])
 * // Returns: ['file:upload:all', 'file:upload:owner']
 */
export const getScopePermissions = (
  permissionKey: keyof typeof PERMISSION_ACTIONS,
  scopes: PermissionScope[] = ['ALL', 'OWNER'],
): string[] => {
  return scopes.map((scope) => {
    const key = `${permissionKey}_${scope}` as `${keyof typeof PERMISSION_ACTIONS}_${PermissionScope}`;
    return RBAC_PERMISSIONS[key];
  });
};

/**
 * Get all permission codes for a given permission action key across all scopes.
 * @param permissionKey - The permission action key (e.g., 'AGENT_READ', 'FILE_UPLOAD')
 * @returns Array of all permission codes for this action
 *
 * @example
 * getAllScopePermissions('AGENT_READ')
 * // Returns: ['agent:read:all', 'agent:read:owner']
 */
export const getAllScopePermissions = (
  permissionKey: keyof typeof PERMISSION_ACTIONS,
): string[] => {
  return getScopePermissions(permissionKey, PERMISSION_SCOPE);
};

/**
 * Get all permission codes that a user should have for a specific resource type.
 * @param resourceType - The resource type (e.g., 'agent', 'file', 'message')
 * @returns Array of all permission codes for this resource type
 *
 * @example
 * getResourceAllPermissions('agent')
 * // Returns: ['agent:read:all', 'agent:read:owner', 'agent:create:all', ...]
 */
export const getResourceAllPermissions = (resourceType: string): string[] => {
  return Object.entries(RBAC_PERMISSIONS)
    .filter(([key]) => {
      const actionKey = key.split('_')[0] as keyof typeof PERMISSION_ACTIONS;
      const permissionValue = PERMISSION_ACTIONS[actionKey];
      return permissionValue.startsWith(`${resourceType}:`);
    })
    .map(([, value]) => value);
};

/**
 * Check if a permission code is valid.
 * @param permissionCode - The permission code to validate
 * @returns Boolean indicating if the permission code is valid
 */
export const isValidPermissionCode = (permissionCode: string): boolean => {
  return Object.values(RBAC_PERMISSIONS).includes(permissionCode);
};

/**
 * Parse a permission code into its components.
 * @param permissionCode - The permission code to parse (e.g., 'agent:read:all')
 * @returns Object containing resource, action, and scope, or null if invalid
 */
export const parsePermissionCode = (
  permissionCode: string,
): { action: string; resource: string; scope: string } | null => {
  const parts = permissionCode.split(':');
  if (parts.length !== 3) return null;

  const [resource, action, scope] = parts;
  return { action, resource, scope };
};

/**
 * Get all unique resource types from the permission definitions.
 * @returns Array of unique resource types
 */
export const getAllResourceTypes = (): string[] => {
  const resourceTypes = new Set<string>();

  Object.values(PERMISSION_ACTIONS).forEach((permission) => {
    const resource = permission.split(':')[0];
    resourceTypes.add(resource);
  });

  return Array.from(resourceTypes);
};

/**
 * Get all unique actions from the permission definitions.
 * @returns Array of unique actions
 */
export const getAllActions = (): string[] => {
  const actions = new Set<string>();

  Object.values(PERMISSION_ACTIONS).forEach((permission) => {
    const action = permission.split(':')[1];
    actions.add(action);
  });

  return Array.from(actions);
};

/**
 * Get all permission keys for a specific action type.
 * @param action - The action type (e.g., 'read', 'create', 'update', 'delete')
 * @returns Array of permission keys that match the action
 */
export const getPermissionsByAction = (action: string): RBAC_PERMISSIONS_KEY[] => {
  return (Object.keys(PERMISSION_ACTIONS) as RBAC_PERMISSIONS_KEY[]).filter((key) => {
    const permissionValue = PERMISSION_ACTIONS[key];
    return permissionValue.split(':')[1] === action;
  });
};

/**
 * Get all permission keys for a specific resource type.
 * @param resource - The resource type (e.g., 'agent', 'file', 'message')
 * @returns Array of permission keys that match the resource
 */
export const getPermissionsByResource = (resource: string): RBAC_PERMISSIONS_KEY[] => {
  return (Object.keys(PERMISSION_ACTIONS) as RBAC_PERMISSIONS_KEY[]).filter((key) => {
    const permissionValue = PERMISSION_ACTIONS[key];
    return permissionValue.split(':')[0] === resource;
  });
};
