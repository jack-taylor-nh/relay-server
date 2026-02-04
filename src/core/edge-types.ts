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
    description: 'Your unique &handle for direct E2EE contact',
    icon: '',
    addressFormat: '&{handle}',
    securityLevel: 'e2ee',
    requiresCustomAddress: true,
    addressPlaceholder: 'yourname',
    addressValidation: /^[a-z0-9_-]{3,32}$/,
    enabled: true,
  },
  {
    id: 'email',
    name: 'Email Alias',
    description: 'Send & receive relay messages through a disposable email address',
    icon: '',
    addressFormat: '{random}@rlymsg.com',
    securityLevel: 'gateway_secured',
    requiresCustomAddress: false,
    enabled: true,
  },
  {
    id: 'contact_link',
    name: 'Contact Link',
    description: 'Share a link for E2EE conversations with anyone, no account required.',
    icon: '',
    addressFormat: 'link.rlymsg.com/{slug}',
    securityLevel: 'e2ee',
    requiresCustomAddress: false,
    enabled: true,
  },
  {
    id: 'discord',
    name: 'Discord Handle',
    description: 'Receive Discord DMs via Relay bot',
    icon: '',
    addressFormat: '&{handle}',
    securityLevel: 'gateway_secured',
    requiresCustomAddress: true,
    addressPlaceholder: 'your_handle',
    addressValidation: /^[a-z0-9_-]{3,32}$/,  // Same format as native handles
    enabled: true,
  },
  // Future edge types can be added here without client changes!
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
