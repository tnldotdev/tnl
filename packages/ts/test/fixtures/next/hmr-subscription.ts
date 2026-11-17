import { loadBindings } from "next/dist/build/swc/index.js";

// next's sync frame precedes client subscriptions, and its hot reloader hides
// their initial issues-only result. observe that result without changing it.
const bindings = await loadBindings();
const createProject = bindings.turbo.createProject;
bindings.turbo.createProject = async (...args) => {
  const result = await createProject(...args);
  const project = result.value;
  const clientHmrEvents = project.clientHmrEvents.bind(project);
  project.clientHmrEvents = (path) => {
    const subscription = clientHmrEvents(path);
    const next = subscription.next.bind(subscription);
    let initial = true;
    subscription.next = async (...nextArgs) => {
      const value = await next(...nextArgs);
      if (initial && !value.done) {
        initial = false;
        process.stdout.write(`\ntnl-next-hmr-subscribed:${path}\n`);
      }
      return value;
    };
    return subscription;
  };
  return result;
};
