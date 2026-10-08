// SPDX-License-Identifier: GPL-2.0

#include <linux/virtio.h>
#include <linux/virtio_config.h>

#if IS_BUILTIN(CONFIG_VIRTIO)

__rust_helper struct virtqueue *
rust_helper_virtio_find_single_vq(struct virtio_device *vdev, vq_callback_t *c,
				  const char *n)
{
	return virtio_find_single_vq(vdev, c, n);
}

__rust_helper void rust_helper_virtio_device_ready(struct virtio_device *vdev)
{
	virtio_device_ready(vdev);
}

__rust_helper bool rust_helper_virtio_has_feature(const struct virtio_device *vdev,
						  unsigned int fbit)
{
	return virtio_has_feature(vdev, fbit);
}

__rust_helper void rust_helper_virtio_cread_bytes(struct virtio_device *vdev,
						  unsigned int offset, void *buf,
						  size_t len)
{
	virtio_cread_bytes(vdev, offset, buf, len);
}

__rust_helper u16 rust_helper_virtio_cread16(struct virtio_device *vdev,
					     unsigned int offset)
{
	__virtio16 v;

	virtio_cread_bytes(vdev, offset, &v, sizeof(v));
	return virtio16_to_cpu(vdev, v);
}

__rust_helper void rust_helper_virtio_del_vqs(struct virtio_device *vdev)
{
	vdev->config->del_vqs(vdev);
}

#endif
