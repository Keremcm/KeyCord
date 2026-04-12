"use strict";

var QWebChannelMessageTypes = {
    signal: 1,
    propertyUpdate: 2,
    init: 3,
    idle: 4,
    debug: 5,
    reply: 6,
    error: 7,
    invokeMethod: 8,
    connectToSignal: 9,
    disconnectFromSignal: 10,
    setProperty: 11
};

var QWebChannel = function (transport, initCallback) {
    if (typeof transport !== "object" || typeof transport.send !== "function") {
        console.error("The QWebChannel transport object is invalid!");
        return;
    }

    var channel = this;
    this.transport = transport;

    this.send = function (data) {
        if (typeof data !== "string") {
            data = JSON.stringify(data);
        }
        channel.transport.send(data);
    }

    this.transport.onmessage = function (message) {
        var data = message.data;
        if (typeof data === "string") {
            data = JSON.parse(data);
        }
        switch (data.type) {
            case QWebChannelMessageTypes.signal:
                channel.handleSignal(data);
                break;
            case QWebChannelMessageTypes.reply:
                channel.handleReply(data);
                break;
            case QWebChannelMessageTypes.propertyUpdate:
                channel.handlePropertyUpdate(data);
                break;
            case QWebChannelMessageTypes.error:
                console.error("An error occurred over QWebChannel: " + data.payload);
                break;
        }
    };

    this.execCallbacks = {};
    this.execId = 0;
    this.exec = function (data, callback) {
        if (!callback) {
            channel.send(data);
            return;
        }
        var id = channel.execId++;
        channel.execCallbacks[id] = callback;
        data.id = id;
        channel.send(data);
    };

    this.handleSignal = function (data) {
        var object = channel.objects[data.object];
        if (object) {
            object.signalEmitted(data.signal, data.args);
        } else {
            console.warn("Unhandled signal: " + data.object + "::" + data.signal);
        }
    }

    this.handleReply = function (data) {
        var callback = channel.execCallbacks[data.id];
        if (callback) {
            callback(data.payload);
            delete channel.execCallbacks[data.id];
        }
    }

    this.handlePropertyUpdate = function (data) {
        for (var i in data.signals) {
            var signal = data.signals[i];
            var object = channel.objects[signal.object];
            if (object) {
                object.propertyUpdate(signal.signals, signal.properties);
            }
        }
    }

    this.debug = function (message) {
        channel.send({ type: QWebChannelMessageTypes.debug, payload: message });
    };

    this.onkey = function (key, callback) {
        channel.exec({ type: QWebChannelMessageTypes.getKey, key: key }, callback);
    }

    this.objects = {};

    this.bind = function (name, object) {
        this.objects[name] = object;
    };

    this.exec({ type: QWebChannelMessageTypes.init }, function (data) {
        for (var name in data) {
            var object = new QObject(name, data[name], channel);
        }
        if (initCallback) {
            initCallback(channel);
        }
    });
};

function QObject(name, data, webChannel) {
    this.__id__ = name;
    webChannel.objects[name] = this;

    // List of signals that are currently connected to.
    this.__signals__ = {};

    var self = this;

    // Create properties, signals and methods
    for (var i = 0; i < data.methods.length; ++i) {
        var method = data.methods[i];
        this[method[0]] = (function (methodName) {
            return function () {
                var args = [];
                var callback;
                for (var j = 0; j < arguments.length; ++j) {
                    if (typeof arguments[j] === "function")
                        callback = arguments[j];
                    else
                        args.push(arguments[j]);
                }

                webChannel.exec({
                    type: QWebChannelMessageTypes.invokeMethod,
                    object: self.__id__,
                    method: methodName,
                    args: args
                }, callback);
            };
        })(method[0]);
    }

    this.propertyUpdate = function (signals, properties) {
        for (var name in properties) {
            this[name] = properties[name];
        }

        for (var name in signals) {
            var signal = signals[name];
            var callbacks = this.__signals__[name];
            if (callbacks) {
                callbacks.forEach(function (callback) {
                    callback.apply(callback, signal);
                });
            }
        }
    };

    this.signalEmitted = function (signalName, args) {
        var callbacks = this.__signals__[signalName];
        if (callbacks) {
            callbacks.forEach(function (callback) {
                callback.apply(callback, args);
            });
        }
    };

    this.connect = function (signalName, callback) {
        if (typeof (callback) !== "function" || !signalName) {
            return;
        }

        if (!this.__signals__[signalName]) {
            this.__signals__[signalName] = [];
            webChannel.exec({
                type: QWebChannelMessageTypes.connectToSignal,
                object: this.__id__,
                signal: signalName
            });
        }

        this.__signals__[signalName].push(callback);
    };

    this.disconnect = function (signalName, callback) {
        if (!signalName || !this.__signals__[signalName]) {
            return;
        }
        if (callback) {
            var index = this.__signals__[signalName].indexOf(callback);
            if (index === -1) {
                return;
            }
            this.__signals__[signalName].splice(index, 1);
            if (this.__signals__[signalName].length > 0) {
                return;
            }
        } else {
            delete this.__signals__[signalName];
        }

        webChannel.exec({
            type: QWebChannelMessageTypes.disconnectFromSignal,
            object: this.__id__,
            signal: signalName
        });
    };

    for (var name in data.properties) {
        this[name] = data.properties[name];
    }
}
