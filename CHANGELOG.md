## 3.3.0 - 05-08-2026

* Update libredirectionio to 3.3.0
* Report rule executions to the agent with the `RULE_COUNT` command, so rules triggered on
  non-logged requests are still counted - only sent when the agent advertises protocol >= 1.1

## 3.2.0 - 26-06-2026

* Update libredirectionio to 3.2.0
* Fix capture backend response headers to pass them to body filters before redirection.io mutates them
* Fix use-after-free / segfault on child exit (mpm_event) introduced in 3.1.2: the connection pool
  cleanup was registered on the parent pool, so the reslist was already freed (with its child pool)
  by the time the cleanup ran. Register it on the reslist pool instead.

## 3.1.3 - 10-06-2026

* Fix memory leaks in error scenario where some resources were not correctly cleaned

## 3.1.2 - 03-06-2026

* Decouple memory drop / alloc when using libredirectionio to avoid separate allocator issue
* Remove focal build
* Make connection pool thread safe to avoid potential race condition when using mpm_event

## 3.1.1 - 16-04-2026

* Use a better field to retrieve client ip (which works better with other modules interaction)
* Reuse ctx in case of internal redirect to filter the correct request

## 3.1.0 - 04-04-2026

* Update libredirectionio to 3.1.0
* Fix potential memory leak when when the agent is no longer available
* Add directive to enable redirectionio tracing, remove log callback

## 3.0.0 - 26-02-2026

* Update libredirectionio to 3.0.0

## 2.9.1 - 25-07-2025

* Correctly clear connections pool after the main pool has been cleaned. In rare cases, excessive log entries were
  generated due to connections not being correctly cleared from the pool.

## 2.9.0 - 28-05-2024

* Update libredirectionio to 2.11.2

## 2.8.0 - 06-02-2024

* Update libredirectionio to 2.10.0
* Fix request time in log
* Add backend duration to log

## 2.7.0 - 03-10-2023

* Update libredirectionio to 2.9.0

## 2.6.0 - 26-05-2023

* Update libredirectionio to 2.8.0

## 2.5.0 - 20-03-2023

* Support new compression format for body filtering: deflate and brotli

## 2.4.4 - 08-12-2022

* Fix segfault on body filtering in some cases
* Fix a memory leak in body filtering, when there is an error on bucket creation

## 2.4.3 - 05-12-2022

* Fix a memory leak on the log callback
* Fix a potential memory leak on the body filtering system

## 2.4.2 - 23-11-2022

* Allow libredirectionio to modify the `Content-Type` header
* Fix using a unix socket for the agent connection

## 2.4.1 - 27-10-2022

* Support gzip compression when filtering body, by updating libredirectionio deps

## 2.4.0 - 07-07-2022

* Fix a bug when multiple rules where used with a backend status code trigger

## 2.3.0 - 13-04-2022

* Add the `RedirectionioTrustedProxies` configuration directive for correct ip
  matching - ([see the documentation](https://redirection.io/documentation/developer-documentation/apache-module#redirectioniotrustedproxies))
* Add support for the IP address trigger (requires the version 2.3 of the agent)
* Add support for the robots.txt action (requires the version 2.3 of the agent)
* Add the possibility to disable log for a specific request using a rule (requires the version 2.3 of the agent)
* Add support for logging the `Content-Type` response header

## 2.2.2 - 22-09-2021

* new release, for new distributions (debian 11 bullseye, and latest ubuntu)

## 2.2.0 - 06-05-2021

* Add the `RedirectionioSetHeader`
  directive - ([see the documentation](https://redirection.io/documentation/developer-documentation/apache-module#redirectioniosetheader))
* Add connection pool management options to the `RedirectionioPass` directive: `min_conns`, `keep_conns`, `max_conns`
  and
  `timeout` - ([see the documentation](https://redirection.io/documentation/developer-documentation/apache-module#redirectioniopass))

## 2.1.0 - 02-02-2021

* Pass the client IP address to the agent
* Better management of possible module conflicts

## 2.0.0 - 11-01-2021

* Send proxy version in logs
* Send content-type in logs
* Use 2.0.0 version of [libredirection](https://github.com/redirectionio/libredirectionio): more matching and actions
  available
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
