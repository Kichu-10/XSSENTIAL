(() => {
    if (window.__xssentinel) {
        return;
    }

    const state = {
        sources: [],
        sinks: [],
        executions: [],
        marker: null
    };
    const truncate = value => String(value ?? "").slice(0, 1000);
    const initialValue = new URL(location.href).searchParams.get("xssentinel");
    state.marker = initialValue ? initialValue.slice(0, 16) : null;
    window.__xssentinel = state;

    function captureSource(name, value) {
        const text = truncate(value);
        if (state.marker && text.includes(state.marker)) {
            state.sources.push({
                source: name,
                value: text,
                timestamp: Date.now()
            });
        }
    }

    function inspectSources() {
        captureSource("location.href", location.href);
        captureSource("location.search", location.search);
        captureSource("location.hash", location.hash);
        captureSource("document.referrer", document.referrer);
        captureSource("window.name", window.name);
    }

    function recordSink(name, value) {
        const text = truncate(value);
        if (!state.marker || !text.includes(state.marker)) {
            return;
        }
        inspectSources();
        state.sinks.push({
            sink: name,
            value: text,
            stack: new Error().stack || "",
            timestamp: Date.now()
        });
    }

    window.__xssentinel_set_marker = marker => {
        state.marker = String(marker);
        inspectSources();
    };

    window.__xssentinel_exec = token => {
        state.executions.push({
            token: String(token),
            timestamp: Date.now()
        });
    };

    const originalGet = URLSearchParams.prototype.get;
    URLSearchParams.prototype.get = function (key) {
        const result = originalGet.call(this, key);
        captureSource(`URLSearchParams.get:${key}`, result);
        return result;
    };

    const originalGetAll = URLSearchParams.prototype.getAll;
    URLSearchParams.prototype.getAll = function (key) {
        const result = originalGetAll.call(this, key);
        captureSource(`URLSearchParams.getAll:${key}`, result.join(","));
        return result;
    };

    for (const property of ["innerHTML", "outerHTML"]) {
        const descriptor = Object.getOwnPropertyDescriptor(
            Element.prototype,
            property
        );
        if (!descriptor || !descriptor.get || !descriptor.set) {
            continue;
        }
        Object.defineProperty(Element.prototype, property, {
            ...descriptor,
            set(value) {
                recordSink(property, value);
                return descriptor.set.call(this, value);
            }
        });
    }

    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (position, value) {
        recordSink("insertAdjacentHTML", value);
        return originalInsertAdjacentHTML.call(this, position, value);
    };

    const originalWrite = Document.prototype.write;
    Document.prototype.write = function (...values) {
        recordSink("document.write", values.join(""));
        return originalWrite.apply(this, values);
    };

    const originalWriteln = Document.prototype.writeln;
    Document.prototype.writeln = function (...values) {
        recordSink("document.writeln", values.join(""));
        return originalWriteln.apply(this, values);
    };

    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function (callback, delay, ...args) {
        if (typeof callback === "string") {
            recordSink("setTimeout(string)", callback);
        }
        return originalSetTimeout.call(this, callback, delay, ...args);
    };

    const originalSetInterval = window.setInterval;
    window.setInterval = function (callback, delay, ...args) {
        if (typeof callback === "string") {
            recordSink("setInterval(string)", callback);
        }
        return originalSetInterval.call(this, callback, delay, ...args);
    };

    const originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
        if (/^on/i.test(name) || name.toLowerCase() === "srcdoc") {
            recordSink(`setAttribute:${name}`, value);
        }
        return originalSetAttribute.call(this, name, value);
    };

    inspectSources();
    window.addEventListener("DOMContentLoaded", inspectSources);
    window.addEventListener("hashchange", inspectSources);
    window.addEventListener("popstate", inspectSources);
})();
