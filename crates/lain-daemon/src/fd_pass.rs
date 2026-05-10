#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

/// Unix Domain Socket fd 传递 (SCM_RIGHTS)
/// 通过 sendmsg/recvmsg 在 daemon 和本地应用之间传递文件描述符
#[cfg(unix)]
pub mod fd_pass {
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use tracing;

    /// 通过 Unix socket 发送一个文件描述符
    pub fn send_fd(socket: &UnixStream, fd: RawFd) -> std::io::Result<()> {
        let fd = fd.as_raw_fd();
        let fds = [fd];

        let msg = b"fd";
        let mut iov = [libc::iovec {
            iov_base: msg.as_ptr() as *mut _,
            iov_len: msg.len(),
        }];

        let mut cmsg_buf = vec![0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&iov as *const _ as *mut _) };

        unsafe { (*cmsg).cmsg_level = libc::SOL_SOCKET; }
        unsafe { (*cmsg).cmsg_type = libc::SCM_RIGHTS; }
        unsafe { (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _; }
        unsafe {
            let data_ptr = libc::CMSG_DATA(cmsg);
            std::ptr::copy_nonoverlapping(fds.as_ptr(), data_ptr as *mut RawFd, 1);
        }

        let mut msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_mut_ptr(),
            msg_iovlen: 1,
            msg_control: cmsg.as_mut_ptr() as *mut _,
            msg_controllen: cmsg.len() as _,
            msg_flags: 0,
        };

        let result = unsafe { libc::sendmsg(socket.as_raw_fd(), &msghdr, 0) };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            tracing::debug!("sent fd {} via SCM_RIGHTS", fd);
            Ok(())
        }
    }

    /// 通过 Unix socket 接收一个文件描述符
    pub fn recv_fd(socket: &UnixStream) -> std::io::Result<RawFd> {
        let mut buf = [0u8; 4];
        let mut iov = [libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        }];

        let mut cmsg_buf = vec![0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];

        let mut msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_mut_ptr(),
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_mut_ptr() as *mut _,
            msg_controllen: cmsg_buf.len() as _,
            msg_flags: 0,
        };

        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msghdr, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
        if cmsg.is_null()
            || unsafe { (*cmsg).cmsg_level != libc::SOL_SOCKET }
            || unsafe { (*cmsg).cmsg_type != libc::SCM_RIGHTS }
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no SCM_RIGHTS in message",
            ));
        }

        let mut fd: RawFd = 0;
        unsafe {
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg) as *const RawFd,
                &mut fd,
                1,
            );
        }

        tracing::debug!("received fd {fd} via SCM_RIGHTS");
        Ok(fd)
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod tests {
        use super::*;
        use std::os::unix::net::UnixStream;

        #[test]
        fn test_fd_pass_roundtrip() {
            let (a, b) = UnixStream::pair().unwrap();
            // Send b's fd through a → b
            let fd_to_send = b.as_raw_fd();
            send_fd(&a, fd_to_send).unwrap();
            // Receive on b's end
            let received_fd = recv_fd(&b).unwrap();
            assert!(received_fd > 0);
            unsafe { libc::close(received_fd); }
        }
    }
}
