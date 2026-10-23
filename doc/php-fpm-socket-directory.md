# Per-daemon PHP-FPM socket directory

Under **PHP → PHP-FPM versions**, an administrator can optionally set a **Socket directory** for each daemon. The API field is `socket_dir` on `FpmDaemons.add` and `FpmDaemons.update`.

- An empty value uses the global `phpfpm.fastcgi_ipcdir` setting for domain pools. Existing installations retain this behavior after migration.
- A nonempty value must be an absolute directory path. It is normalized with a trailing slash. Choose a short path: generated UNIX socket paths are limited to 100 bytes, including the filename. Existing fallbacks to numeric domain/customer IDs still apply; an unusable path fails explicitly.
- The generated FPM pool and Apache/NGINX FastCGI configuration obtain the same path from `Fpm::getSocketFile()`.
- An empty daemon's dummy pool uses its explicit socket directory, or its historical `/run/` location when no override is set.
- Existing directory ownership and ACLs are preserved. Provision container-specific directories with suitable ownership and access for both FPM and the host webserver before starting the runtime.

## Container example

For a daemon using `/run/php56-customer/`, mount the directory at **the same absolute path** inside the container:

```yaml
volumes:
  - type: bind
    source: /run/php56-customer
    target: /run/php56-customer
  - type: bind
    source: /opt/php56-customer/pools
    target: /etc/php/5.6/fpm/froxlor-pool.d
    read_only: true
```

Set the daemon's configuration directory to `/opt/php56-customer/pools/`, its socket directory to `/run/php56-customer/`, and its restart command to an administrator-owned wrapper that validates and reloads this runtime. The container's main FPM configuration includes `/etc/php/5.6/fpm/froxlor-pool.d/*.conf`.

Do not expose the host's shared PHP socket directory to an isolated customer runtime. Mount the generated pool directory rather than individual pool files: Froxlor removes and recreates them during regeneration. Runtime directories under `/run` require boot-time provisioning, such as systemd-tmpfiles, with dependency ordering for container startup.

This feature only selects socket paths. It does not create containers, build images, provision UNIX identities, implement runtime monitoring, or grant customers Docker access.

## Verification

Check both the pool's `listen` directive and the webserver's FastCGI endpoint after regeneration. Verify syntax, reload, request handling, socket permissions, and boot-time recreation in a staging environment. Existing daemons with an empty override must retain their previous domain socket paths.
