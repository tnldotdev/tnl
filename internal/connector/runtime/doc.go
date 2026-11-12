// package runtime owns a prepared connector context, its listeners, renewal,
// fixed-expiry fence, and local connection-handle API. connector operations supply
// the backend and join this owner's work. stream establishes visitor connections;
// neither package calls back into connector root orchestration.
package runtime
