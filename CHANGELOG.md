## 2.1.0 - 02-02-2021

 * Pass the client IP address to the agent
 * Better management of possible module conflicts

## 2.0.0 - 11-01-2021

 * Send proxy version in logs
 * Send content-type in logs
 * Use 2.0.0 version of [libredirection](https://github.com/redirectionio/libredirectionio): more matching and actions available
 * **[BC BREAK]** New proxy protocol: please update the agent when updating the proxy to the 2.0 branch

## 0.3.2 - 25-02-2019

 * Fix bad response status code in log when using apache rewrite module

## 0.3.1 - 19-02-2019

 * Fix default endpoint for agent when it's not set

## 0.3.0 - 15-02-2019

 * Send request method in logs
 * Add support for filtering header and body response with the agent

## 0.2.0 - 18-01-2019

 * Add support for matching redirection on response status code
 * Stability improvements
    * Fix potential segfault when receiving bad response from agent
    * Fix memory leak issues

## 0.1.0 - 15-11-2018

 * Initial release
