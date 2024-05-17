---
page_title: "synology_filestation_cloud_init Resource - synology"
subcategory: "FileStation"
description: |-
  A file on the Synology NAS Filestation.
---

# synology_filestation_cloud_init (Resource)

A file on the Synology NAS Filestation.


## Example Usage

```terraform
resource "synology_filestation_cloud_init" "foo" {
  path           = "/data/foo/bar/test.iso"
  user_data      = "#cloud-config\n\nusers:\n  - name: test\n    groups: sudo\n    shell: /bin/bash\n    sudo: ['ALL=(ALL) NOPASSWD:ALL']\n    ssh_authorized_keys:\n      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf7"
  create_parents = true
  overwrite      = true
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `meta_data` (String) Meta data content.
- `network_config` (String) Network config content.
- `path` (String) A destination folder path starting with a shared folder to which files can be uploaded.
- `user_data` (String) User data content.

### Optional

- `create_parents` (Boolean) Create parent folder(s) if none exist.
- `overwrite` (Boolean) Overwrite the destination file if one exists.

### Read-Only

- `access_time` (Number) The time the file was last accessed.
- `change_time` (Number) The time the file was last changed.
- `create_time` (Number) The time the file was created.
- `modified_time` (Number) The time the file was last modified.