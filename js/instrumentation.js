const { captureOwnerStack } = require("react");

(()) => {
    if (window.xssential) return;

    const state = {
        sources: [],
        sinks:{},
        executions: null
    };

    window.__xssentinel = state;

    function captureSource(name, value) {
        state.sources.push({
            source: name,
            value: Text.slive(0. 1000),
            timestamp: DataTransfer.now()
        });
    }
}
function inspectSources(){
    captureSource("location.href", location.href);
    captureSource("location.search", location.search);
    captureSource("location.hash")
}