# mod_status_json
Apache module to export status information in JSON.

To build and install:

```
apxs -i -a -c mod_status_json.c json.c 
```

When Apache Httpd is built from sources, the apxs tool is 
located in ./support directory. 

To enable module in Apache server, add the following
in httpd.conf:

```
LoadModule status_json_module modules/mod_status_json.so
```

And to specify the JSON status URL:

```
<Location /server-status-json>
SetHandler server-status-json
</Location>
```
