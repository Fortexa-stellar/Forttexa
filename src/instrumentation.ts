export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    // Keep the database driver out of the Edge instrumentation bundle.
    const { registerNodeInstrumentation } = await import("./instrumentation.node");
    await registerNodeInstrumentation();
  }
}