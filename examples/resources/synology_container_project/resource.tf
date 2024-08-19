resource "synology_container_project" "foo" {
  name = "foo"

  services = {
    "bar" = {
      image = {
        name = "nginx"
        tag  = "latest"
      }

      port = {
        container_port = 80
        host_port      = 80
      }

      logging = {
        driver = "json-file"
      }
    }
  }
}
