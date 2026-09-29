// VibeOS port of esbuild 0.25.0's Node transport. Shared upstream option,
// protocol, result, diagnostic and source-map logic above remains intact.
// Each operation has its own upstream channel (request ID zero). The native
// queue serializes admitted WASI instances without subprocesses or workers.
var version = "0.25.0";
function vibeosUnsupported(name) {
  const error = new Error(`VibeOS esbuild port does not support ${name}`);
  error.code = "ENOTSUP";
  return error;
}
function vibeosBridge() {
  const bridge = globalThis[Symbol.for("vibeos.esbuild")];
  if (!bridge) throw vibeosUnsupported("execution outside the VibeOS toolkit runtime");
  return bridge;
}
function vibeosChannel(input, options, sync, done) {
  if ((typeof input === "string" && encodeUTF8(input).length > 1024 * 1024) ||
      (input instanceof Uint8Array && input.length > 1024 * 1024)) {
    const error = new Error("VibeOS esbuild transform input exceeds 1 MiB");
    error.code = "EFBIG";
    throw error;
  }
  let packet;
  const channel = createChannel({
    writeToStdin(bytes) {
      if (packet) throw new Error("VibeOS esbuild expects one transform request");
      packet = bytes;
    },
    isSync: sync,
    hasFS: false,
    vibeos: true,
    esbuild: node_exports
  });
  channel.service.transform({
    callName: sync ? "transformSync" : "transform", refs: null, input,
    options: options || {}, isTTY: false,
    fs: {
      writeFile(_contents, callback) { callback(null); },
      readFile(_path, callback) { callback(vibeosUnsupported("temporary files"), null); }
    },
    callback: done
  });
  return { channel, packet };
}
var transformSync = (input, options) => {
  const bridge = vibeosBridge();
  let result, failure, complete = false;
  const { channel, packet } = vibeosChannel(input, options, true, (error, value) => {
    complete = true; failure = error; result = value;
  });
  if (packet) {
    try { channel.readFromStdout(bridge.transformSync(packet)); }
    finally { channel.afterClose(null); }
  }
  if (failure) throw failure;
  if (!complete) throw new Error("VibeOS esbuild returned no transform response");
  return result;
};
var transform = (input, options) => new Promise((resolve, reject) => {
  const bridge = vibeosBridge();
  const { channel, packet } = vibeosChannel(input, options, false,
    (error, value) => error ? reject(error) : resolve(value));
  if (!packet) return; // Upstream option validation has already called back.
  bridge.transform(packet).then(bytes => {
    try { channel.readFromStdout(bytes); }
    catch (error) { reject(error); }
    finally { channel.afterClose(null); }
  }, error => { channel.afterClose(error); reject(error); });
});
var buildSync = () => { throw vibeosUnsupported("build"); };
var build = () => Promise.reject(vibeosUnsupported("build"));
var context = () => Promise.reject(vibeosUnsupported("context/watch/serve"));
var formatMessagesSync = () => { throw vibeosUnsupported("formatMessages"); };
var formatMessages = () => Promise.reject(vibeosUnsupported("formatMessages"));
var analyzeMetafileSync = () => { throw vibeosUnsupported("analyzeMetafile"); };
var analyzeMetafile = () => Promise.reject(vibeosUnsupported("analyzeMetafile"));
// The one-shot transport has no persistent child process to stop. Active
// transforms remain owned by the invocation until completion or teardown.
var stop = () => Promise.resolve();
var initializeWasCalled = false;
var initialize = (options) => {
  options = validateInitializeOptions(options || {});
  if (options.wasmURL || options.wasmModule || options.worker)
    throw vibeosUnsupported("custom WebAssembly modules or workers");
  if (initializeWasCalled) throw new Error('Cannot call "initialize" more than once');
  vibeosBridge();
  initializeWasCalled = true;
  return Promise.resolve();
};
