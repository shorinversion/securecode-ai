# Deployment assets

`deploy/docker/` contains pinned build definitions for the runtime, control
plane, worker and isolated repair validator. Build all runtime images with:

```powershell
./deploy/docker/build-images.ps1
./deploy/docker/repair-validator-build.ps1
```

`deploy/gitlab/trusted-audit.yml` is the trusted GitLab audit project template.
Replace only the invalid registry host in its digest-pinned worker image after
publishing the identical image digest to your registry. Keep secrets in the
trusted project and never expose a privileged Docker socket to merge requests.
