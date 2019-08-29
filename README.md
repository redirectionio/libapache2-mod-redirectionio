# About

Apache HTTP module to do redirections on data coming from https://redirection.io/

## Installation

When using the default apache version of your distribution use this documentation to install the module
https://redirection.io/documentation/developer-documentation/apache-module

### Manual

To manually build this library you will need to compile first the [libredirectionio library](https://github.com/redirectionio/libredirectionio)
in some path (e.g. `/tmp/libredirectionio`)

You will need [apxs](https://httpd.apache.org/docs/2.4/programs/apxs.html) installed and available

Then execute the following command:

```
autoreconf -i
./configure
make
```

You can run `make install` to install your module to the current apache2 module folder (you may need root permissions in order to do so).

## Directives

[See this documentation](https://redirection.io/documentation/developer-documentation/apache-module#module-configuration-directives) for available directives

##  License

This code is licensed under the MIT License - see the  [LICENSE](./LICENSE.md)  file for details.
