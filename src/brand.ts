/**
 * Product identity in one place. The name is provisional: change it here (or
 * set UNBOX_PRODUCT_NAME at runtime) instead of editing other files. Domains,
 * handles and trademarks for this name have NOT been verified.
 *
 * Configuration keeps the stable UNBOX_ environment prefix even if the
 * display name changes.
 */
export const BRAND = {
  name: 'UnboxAnyRepo',
  /** Lowercase, filename- and user-agent-safe form of the name. */
  slug: 'unboxanyrepo',
  tagline: 'From GitHub link to running project.',
  description:
    'Paste a public GitHub repository URL to get a structured source and security analysis, clear setup requirements, and a preview of supported projects or instructions to run them locally.',
  version: '0.2.0',
} as const;

/** Filename- and header-safe slug derived from a (possibly overridden) product name. */
export function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || BRAND.slug;
}
