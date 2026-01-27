/**
 * LEGACY COMPATIBILITY LAYER
 * ===========================
 * This file now serves as a backward compatibility layer.
 * All actual implementation has been moved to src/database/
 * 
 * Migration path:
 * - Old code: import { getStore } from './lib/store.js'
 * - New code: import { store } from './database/index.js'
 * 
 * This file will be removed in a future version once all
 * external dependencies are migrated.
 */

// Re-export everything from the new architecture
export * from '../database/schemas.js';
export { Store, store } from '../database/index.js';

// Backward compatibility for getStore() pattern
import { store } from '../database/index.js';

/**
 * @deprecated Use `import { store } from './database/index.js'` instead
 */
export const getStore = (): typeof store => store;

/**
 * @deprecated Use `import { store } from './database/index.js'` instead
 */
export default getStore;
