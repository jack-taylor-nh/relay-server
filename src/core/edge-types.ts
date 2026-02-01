/**
 * Edge Type Registry
 * 
 * Server-side source of truth for available edge types.
 * Clients fetch this dynamically to build UI.
 */

export interface EdgeTypeDefinition {
  id: string;
  name: string;
  description: string;
  icon: string;
  addressFormat: string;
  securityLevel: 'e2ee' | 'gateway_secured';
  requiresCustomAddress: boolean;
  addressPlaceholder?: string;
  addressValidation?: RegExp;
  enabled: boolean;
}

/**
 * Registry of all available edge types
 */
export const EDGE_TYPES: EdgeTypeDefinition[] = [
  {
    id: 'native',
    name: 'Relay Handle',
    description: 'Your unique @handle for direct E2EE contact',
    icon: '🏷️',
    addressFormat: '@{handle}',
    securityLevel: 'e2ee',
    requiresCustomAddress: true,
    addressPlaceholder: 'yourname',
    addressValidation: /^[a-z0-9_-]{3,32}$/,
    enabled: true,
  },
  {
    id: 'email',
    name: 'Email Alias',
    description: 'Receive emails at a disposable address',
    icon: '📧',
    addressFormat: '{random}@rlymsg.com',
    securityLevel: 'gateway_secured',
    requiresCustomAddress: false,
    enabled: true,
  },
  {
    id: 'contact_link',
    name: 'Contact Link',
    description: 'Public contact form for your website',
    icon: '🔗',
    addressFormat: 'rlymsg.com/c/{slug}',
    securityLevel: 'gateway_secured',
    requiresCustomAddress: false,
    enabled: true,
  },
  // Future edge types can be added here without client changes!
  // {
  //   id: 'discord',
  //   name: 'Discord',
  //   description: 'Receive Discord DMs via Relay',
  //   icon: '💬',
  //   addressFormat: 'discord:{username}',
  //   securityLevel: 'gateway_secured',
  //   requiresCustomAddress: true,
  //   addressPlaceholder: 'discord_username',
  //   enabled: false,  // Not ready yet
  // },
];

/**
 * Get all enabled edge types
 */
export function getAvailableEdgeTypes(): EdgeTypeDefinition[] {
  return EDGE_TYPES.filter(t => t.enabled);
}

/**
 * Get edge type definition by ID
 */
export function getEdgeType(id: string): EdgeTypeDefinition | undefined {
  return EDGE_TYPES.find(t => t.id === id);
}

/**
 * Validate custom address for edge type
 */
export function validateEdgeAddress(typeId: string, address: string): boolean {
  const type = getEdgeType(typeId);
  if (!type) return false;
  if (!type.requiresCustomAddress) return true;
  if (!type.addressValidation) return true;
  return type.addressValidation.test(address);
}
