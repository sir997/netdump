// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

pub use self::imp::*;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::transmute_ptr_to_ref)]
#[allow(clippy::upper_case_acronyms)]
#[warn(single_use_lifetimes)]
mod imp {
    use libbpf_rs::libbpf_sys;
    use libbpf_rs::skel::OpenSkel;
    use libbpf_rs::skel::Skel;
    use libbpf_rs::skel::SkelBuilder;

    fn build_skel_config(
    ) -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>> {
        let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
        builder.name("xdp_bpf").map("rb", false).prog("xdp_pass");

        builder.build()
    }

    #[derive(Default)]
    pub struct XdpSkelBuilder {
        pub obj_builder: libbpf_rs::ObjectBuilder,
    }

    impl<'a> SkelBuilder<'a> for XdpSkelBuilder {
        type Output = OpenXdpSkel<'a>;
        fn open(mut self) -> libbpf_rs::Result<OpenXdpSkel<'a>> {
            let mut skel_config = build_skel_config()?;
            let open_opts = self.obj_builder.opts(std::ptr::null());

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            Ok(OpenXdpSkel { obj, skel_config })
        }

        fn open_opts(
            self,
            open_opts: libbpf_sys::bpf_object_open_opts,
        ) -> libbpf_rs::Result<OpenXdpSkel<'a>> {
            let mut skel_config = build_skel_config()?;

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            Ok(OpenXdpSkel { obj, skel_config })
        }

        fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {
            &self.obj_builder
        }
        fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {
            &mut self.obj_builder
        }
    }

    pub struct OpenXdpMaps<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenXdpMaps<'_> {
        pub fn rb(&self) -> &libbpf_rs::OpenMap {
            self.inner.map("rb").unwrap()
        }
    }

    pub struct OpenXdpMapsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenXdpMapsMut<'_> {
        pub fn rb(&mut self) -> &mut libbpf_rs::OpenMap {
            self.inner.map_mut("rb").unwrap()
        }
    }

    pub struct OpenXdpProgs<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenXdpProgs<'_> {
        pub fn xdp_pass(&self) -> &libbpf_rs::OpenProgram {
            self.inner.prog("xdp_pass").unwrap()
        }
    }

    pub struct OpenXdpProgsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenXdpProgsMut<'_> {
        pub fn xdp_pass(&mut self) -> &mut libbpf_rs::OpenProgram {
            self.inner.prog_mut("xdp_pass").unwrap()
        }
    }

    pub struct OpenXdpSkel<'a> {
        pub obj: libbpf_rs::OpenObject,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
    }

    impl<'a> OpenSkel for OpenXdpSkel<'a> {
        type Output = XdpSkel<'a>;
        fn load(mut self) -> libbpf_rs::Result<XdpSkel<'a>> {
            let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            let obj = unsafe { libbpf_rs::Object::from_ptr(self.obj.take_ptr())? };

            Ok(XdpSkel {
                obj,
                skel_config: self.skel_config,
                links: XdpLinks::default(),
            })
        }

        fn open_object(&self) -> &libbpf_rs::OpenObject {
            &self.obj
        }

        fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {
            &mut self.obj
        }
    }
    impl OpenXdpSkel<'_> {
        pub fn progs(&self) -> OpenXdpProgs<'_> {
            OpenXdpProgs { inner: &self.obj }
        }

        pub fn progs_mut(&mut self) -> OpenXdpProgsMut<'_> {
            OpenXdpProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> OpenXdpMaps<'_> {
            OpenXdpMaps { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> OpenXdpMapsMut<'_> {
            OpenXdpMapsMut {
                inner: &mut self.obj,
            }
        }
    }

    pub struct XdpMaps<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl XdpMaps<'_> {
        pub fn rb(&self) -> &libbpf_rs::Map {
            self.inner.map("rb").unwrap()
        }
    }

    pub struct XdpMapsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl XdpMapsMut<'_> {
        pub fn rb(&mut self) -> &mut libbpf_rs::Map {
            self.inner.map_mut("rb").unwrap()
        }
    }

    pub struct XdpProgs<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl XdpProgs<'_> {
        pub fn xdp_pass(&self) -> &libbpf_rs::Program {
            self.inner.prog("xdp_pass").unwrap()
        }
    }

    pub struct XdpProgsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl XdpProgsMut<'_> {
        pub fn xdp_pass(&mut self) -> &mut libbpf_rs::Program {
            self.inner.prog_mut("xdp_pass").unwrap()
        }
    }

    #[derive(Default)]
    pub struct XdpLinks {
        pub xdp_pass: Option<libbpf_rs::Link>,
    }

    pub struct XdpSkel<'a> {
        pub obj: libbpf_rs::Object,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
        pub links: XdpLinks,
    }

    unsafe impl Send for XdpSkel<'_> {}
    unsafe impl Sync for XdpSkel<'_> {}

    impl Skel for XdpSkel<'_> {
        fn object(&self) -> &libbpf_rs::Object {
            &self.obj
        }

        fn object_mut(&mut self) -> &mut libbpf_rs::Object {
            &mut self.obj
        }

        fn attach(&mut self) -> libbpf_rs::Result<()> {
            let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::System(-ret));
            }

            self.links = XdpLinks {
                xdp_pass: (|| {
                    Ok(core::ptr::NonNull::new(self.skel_config.prog_link_ptr(0)?)
                        .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }))
                })()?,
            };

            Ok(())
        }
    }
    impl XdpSkel<'_> {
        pub fn progs(&self) -> XdpProgs<'_> {
            XdpProgs { inner: &self.obj }
        }

        pub fn progs_mut(&mut self) -> XdpProgsMut<'_> {
            XdpProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> XdpMaps<'_> {
            XdpMaps { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> XdpMapsMut<'_> {
            XdpMapsMut {
                inner: &mut self.obj,
            }
        }
    }

    const DATA: &[u8] = &[
        127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 72, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0,
        0, 64, 0, 9, 0, 1, 0, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97, 98,
        0, 120, 100, 112, 0, 108, 105, 99, 101, 110, 115, 101, 0, 46, 109, 97, 112, 115, 0, 120,
        100, 112, 46, 98, 112, 102, 46, 99, 0, 76, 66, 66, 48, 95, 57, 0, 76, 66, 66, 48, 95, 54,
        0, 76, 66, 66, 48, 95, 56, 0, 120, 100, 112, 95, 112, 97, 115, 115, 0, 114, 98, 0, 76, 73,
        67, 69, 78, 83, 69, 0, 46, 114, 101, 108, 120, 100, 112, 0, 46, 66, 84, 70, 0, 46, 66, 84,
        70, 46, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 35, 0, 0, 0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 0, 0, 0, 0,
        0, 3, 0, 104, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0, 3, 0, 248, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59, 0, 0, 0, 0, 0, 3, 0, 8, 2, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0, 18, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 2, 0, 0, 0,
        0, 0, 0, 75, 0, 0, 0, 17, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 78, 0,
        0, 0, 17, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 183, 6, 0, 0, 0, 0, 0,
        0, 97, 24, 4, 0, 0, 0, 0, 0, 97, 25, 0, 0, 0, 0, 0, 0, 191, 145, 0, 0, 0, 0, 0, 0, 7, 1, 0,
        0, 14, 0, 0, 0, 45, 129, 71, 0, 0, 0, 0, 0, 24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 183, 2, 0, 0, 48, 0, 0, 0, 183, 3, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 131, 0, 0, 0, 191, 7,
        0, 0, 0, 0, 0, 0, 183, 6, 0, 0, 2, 0, 0, 0, 21, 7, 63, 0, 0, 0, 0, 0, 183, 1, 0, 0, 12, 0,
        0, 0, 105, 146, 12, 0, 0, 0, 0, 0, 220, 2, 0, 0, 16, 0, 0, 0, 21, 2, 13, 0, 221, 134, 0, 0,
        85, 2, 46, 0, 0, 8, 0, 0, 191, 146, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 84, 2, 0, 0, 45, 130, 43,
        0, 0, 0, 0, 0, 191, 146, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0, 196, 0, 0, 0, 97, 35, 12, 0, 0, 0,
        0, 0, 220, 3, 0, 0, 16, 0, 0, 0, 99, 55, 16, 0, 0, 0, 0, 0, 97, 34, 16, 0, 0, 0, 0, 0, 220,
        2, 0, 0, 16, 0, 0, 0, 99, 39, 32, 0, 0, 0, 0, 0, 5, 0, 34, 0, 0, 0, 0, 0, 191, 146, 0, 0,
        0, 0, 0, 0, 7, 2, 0, 0, 4, 7, 0, 0, 45, 130, 31, 0, 0, 0, 0, 0, 191, 146, 0, 0, 0, 0, 0, 0,
        7, 2, 0, 0, 196, 0, 0, 0, 183, 3, 0, 0, 8, 0, 0, 0, 97, 36, 8, 0, 0, 0, 0, 0, 220, 4, 0, 0,
        32, 0, 0, 0, 99, 71, 16, 0, 0, 0, 0, 0, 183, 4, 0, 0, 24, 0, 0, 0, 97, 37, 24, 0, 0, 0, 0,
        0, 220, 5, 0, 0, 32, 0, 0, 0, 99, 87, 32, 0, 0, 0, 0, 0, 191, 37, 0, 0, 0, 0, 0, 0, 15, 53,
        0, 0, 0, 0, 0, 0, 97, 83, 4, 0, 0, 0, 0, 0, 220, 3, 0, 0, 32, 0, 0, 0, 99, 55, 20, 0, 0, 0,
        0, 0, 15, 66, 0, 0, 0, 0, 0, 0, 97, 35, 4, 0, 0, 0, 0, 0, 220, 3, 0, 0, 32, 0, 0, 0, 99,
        55, 36, 0, 0, 0, 0, 0, 97, 83, 8, 0, 0, 0, 0, 0, 220, 3, 0, 0, 32, 0, 0, 0, 99, 55, 24, 0,
        0, 0, 0, 0, 97, 35, 8, 0, 0, 0, 0, 0, 220, 3, 0, 0, 32, 0, 0, 0, 99, 55, 40, 0, 0, 0, 0, 0,
        97, 83, 12, 0, 0, 0, 0, 0, 220, 3, 0, 0, 32, 0, 0, 0, 99, 55, 28, 0, 0, 0, 0, 0, 97, 34,
        12, 0, 0, 0, 0, 0, 220, 2, 0, 0, 32, 0, 0, 0, 99, 39, 44, 0, 0, 0, 0, 0, 191, 146, 0, 0, 0,
        0, 0, 0, 15, 18, 0, 0, 0, 0, 0, 0, 105, 33, 0, 0, 0, 0, 0, 0, 220, 1, 0, 0, 16, 0, 0, 0,
        107, 23, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 5, 0, 0, 0, 123, 7, 8, 0, 0, 0, 0, 0, 31, 152, 0,
        0, 0, 0, 0, 0, 99, 135, 4, 0, 0, 0, 0, 0, 191, 113, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 0, 0,
        0, 0, 133, 0, 0, 0, 132, 0, 0, 0, 191, 96, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 68,
        117, 97, 108, 32, 66, 83, 68, 47, 71, 80, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 159, 235, 1, 0, 24, 0, 0,
        0, 0, 0, 0, 0, 96, 4, 0, 0, 96, 4, 0, 0, 29, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0,
        0, 0, 4, 0, 0, 0, 27, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 2, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0,
        4, 0, 0, 0, 0, 0, 2, 0, 0, 4, 16, 0, 0, 0, 25, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0,
        0, 5, 0, 0, 0, 64, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 14, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 2, 10, 0, 0, 0, 45, 0, 0, 0, 6, 0, 0, 4, 24, 0, 0, 0, 52, 0, 0, 0, 11, 0, 0, 0, 0,
        0, 0, 0, 57, 0, 0, 0, 11, 0, 0, 0, 32, 0, 0, 0, 66, 0, 0, 0, 11, 0, 0, 0, 64, 0, 0, 0, 76,
        0, 0, 0, 11, 0, 0, 0, 96, 0, 0, 0, 92, 0, 0, 0, 11, 0, 0, 0, 128, 0, 0, 0, 107, 0, 0, 0,
        11, 0, 0, 0, 160, 0, 0, 0, 122, 0, 0, 0, 0, 0, 0, 8, 12, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 1,
        4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 13, 2, 0, 0, 0, 141, 0, 0, 0, 9, 0, 0, 0,
        145, 0, 0, 0, 1, 0, 0, 12, 13, 0, 0, 0, 154, 0, 0, 0, 3, 0, 0, 4, 14, 0, 0, 0, 161, 0, 0,
        0, 17, 0, 0, 0, 0, 0, 0, 0, 168, 0, 0, 0, 17, 0, 0, 0, 48, 0, 0, 0, 177, 0, 0, 0, 18, 0, 0,
        0, 96, 0, 0, 0, 185, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
        0, 0, 0, 0, 16, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 199, 0, 0, 0, 0, 0, 0, 8, 19, 0, 0, 0,
        206, 0, 0, 0, 0, 0, 0, 8, 20, 0, 0, 0, 212, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 16, 0, 0, 0,
        227, 0, 0, 0, 10, 0, 0, 132, 20, 0, 0, 0, 233, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 4, 237, 0, 0,
        0, 22, 0, 0, 0, 4, 0, 0, 4, 245, 0, 0, 0, 22, 0, 0, 0, 8, 0, 0, 0, 249, 0, 0, 0, 18, 0, 0,
        0, 16, 0, 0, 0, 1, 1, 0, 0, 18, 0, 0, 0, 32, 0, 0, 0, 4, 1, 0, 0, 18, 0, 0, 0, 48, 0, 0, 0,
        13, 1, 0, 0, 22, 0, 0, 0, 64, 0, 0, 0, 17, 1, 0, 0, 22, 0, 0, 0, 72, 0, 0, 0, 26, 1, 0, 0,
        23, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 96, 0, 0, 0, 32, 1, 0, 0, 0, 0, 0, 8,
        16, 0, 0, 0, 37, 1, 0, 0, 0, 0, 0, 8, 19, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 5, 8, 0, 0, 0, 0,
        0, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 45, 1, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0,
        0, 4, 8, 0, 0, 0, 51, 1, 0, 0, 26, 0, 0, 0, 0, 0, 0, 0, 57, 1, 0, 0, 26, 0, 0, 0, 32, 0, 0,
        0, 63, 1, 0, 0, 0, 0, 0, 8, 11, 0, 0, 0, 70, 1, 0, 0, 7, 0, 0, 132, 40, 0, 0, 0, 78, 1, 0,
        0, 22, 0, 0, 0, 0, 0, 0, 4, 237, 0, 0, 0, 22, 0, 0, 0, 4, 0, 0, 4, 87, 1, 0, 0, 28, 0, 0,
        0, 8, 0, 0, 0, 96, 1, 0, 0, 18, 0, 0, 0, 32, 0, 0, 0, 108, 1, 0, 0, 22, 0, 0, 0, 48, 0, 0,
        0, 116, 1, 0, 0, 22, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 3, 0, 0, 0, 0, 22, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 5, 32,
        0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 45, 1, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 2, 0, 0, 4, 32, 0, 0, 0, 51, 1, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 57, 1, 0, 0, 31, 0, 0,
        0, 128, 0, 0, 0, 126, 1, 0, 0, 1, 0, 0, 4, 16, 0, 0, 0, 135, 1, 0, 0, 32, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 3, 0, 0, 5, 16, 0, 0, 0, 141, 1, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 150, 1, 0,
        0, 34, 0, 0, 0, 0, 0, 0, 0, 160, 1, 0, 0, 35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
        0, 0, 0, 0, 22, 0, 0, 0, 4, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 18,
        0, 0, 0, 4, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 26, 0, 0, 0, 4, 0, 0,
        0, 4, 0, 0, 0, 170, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0,
        0, 0, 0, 36, 0, 0, 0, 4, 0, 0, 0, 13, 0, 0, 0, 175, 1, 0, 0, 0, 0, 0, 14, 37, 0, 0, 0, 1,
        0, 0, 0, 11, 5, 0, 0, 1, 0, 0, 15, 13, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 19,
        5, 0, 0, 1, 0, 0, 15, 16, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 105, 110, 116,
        0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90, 69, 95, 84, 89, 80, 69, 95, 95, 0, 116, 121,
        112, 101, 0, 109, 97, 120, 95, 101, 110, 116, 114, 105, 101, 115, 0, 114, 98, 0, 120, 100,
        112, 95, 109, 100, 0, 100, 97, 116, 97, 0, 100, 97, 116, 97, 95, 101, 110, 100, 0, 100, 97,
        116, 97, 95, 109, 101, 116, 97, 0, 105, 110, 103, 114, 101, 115, 115, 95, 105, 102, 105,
        110, 100, 101, 120, 0, 114, 120, 95, 113, 117, 101, 117, 101, 95, 105, 110, 100, 101, 120,
        0, 101, 103, 114, 101, 115, 115, 95, 105, 102, 105, 110, 100, 101, 120, 0, 95, 95, 117, 51,
        50, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 105, 110, 116, 0, 99, 116, 120, 0, 120,
        100, 112, 95, 112, 97, 115, 115, 0, 101, 116, 104, 104, 100, 114, 0, 104, 95, 100, 101,
        115, 116, 0, 104, 95, 115, 111, 117, 114, 99, 101, 0, 104, 95, 112, 114, 111, 116, 111, 0,
        117, 110, 115, 105, 103, 110, 101, 100, 32, 99, 104, 97, 114, 0, 95, 95, 98, 101, 49, 54,
        0, 95, 95, 117, 49, 54, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 115, 104, 111, 114,
        116, 0, 105, 112, 104, 100, 114, 0, 105, 104, 108, 0, 118, 101, 114, 115, 105, 111, 110, 0,
        116, 111, 115, 0, 116, 111, 116, 95, 108, 101, 110, 0, 105, 100, 0, 102, 114, 97, 103, 95,
        111, 102, 102, 0, 116, 116, 108, 0, 112, 114, 111, 116, 111, 99, 111, 108, 0, 99, 104, 101,
        99, 107, 0, 95, 95, 117, 56, 0, 95, 95, 115, 117, 109, 49, 54, 0, 97, 100, 100, 114, 115,
        0, 115, 97, 100, 100, 114, 0, 100, 97, 100, 100, 114, 0, 95, 95, 98, 101, 51, 50, 0, 105,
        112, 118, 54, 104, 100, 114, 0, 112, 114, 105, 111, 114, 105, 116, 121, 0, 102, 108, 111,
        119, 95, 108, 98, 108, 0, 112, 97, 121, 108, 111, 97, 100, 95, 108, 101, 110, 0, 110, 101,
        120, 116, 104, 100, 114, 0, 104, 111, 112, 95, 108, 105, 109, 105, 116, 0, 105, 110, 54,
        95, 97, 100, 100, 114, 0, 105, 110, 54, 95, 117, 0, 117, 54, 95, 97, 100, 100, 114, 56, 0,
        117, 54, 95, 97, 100, 100, 114, 49, 54, 0, 117, 54, 95, 97, 100, 100, 114, 51, 50, 0, 99,
        104, 97, 114, 0, 76, 73, 67, 69, 78, 83, 69, 0, 47, 114, 111, 111, 116, 47, 110, 101, 116,
        100, 117, 109, 112, 47, 115, 114, 99, 47, 98, 112, 102, 47, 120, 100, 112, 46, 98, 112,
        102, 46, 99, 0, 105, 110, 116, 32, 120, 100, 112, 95, 112, 97, 115, 115, 40, 115, 116, 114,
        117, 99, 116, 32, 120, 100, 112, 95, 109, 100, 32, 42, 99, 116, 120, 41, 0, 32, 32, 32, 32,
        118, 111, 105, 100, 32, 42, 100, 97, 116, 97, 95, 101, 110, 100, 32, 61, 32, 40, 118, 111,
        105, 100, 32, 42, 41, 40, 117, 54, 52, 41, 99, 116, 120, 45, 62, 100, 97, 116, 97, 95, 101,
        110, 100, 59, 0, 32, 32, 32, 32, 118, 111, 105, 100, 32, 42, 100, 97, 116, 97, 32, 61, 32,
        40, 118, 111, 105, 100, 32, 42, 41, 40, 117, 54, 52, 41, 99, 116, 120, 45, 62, 100, 97,
        116, 97, 59, 0, 32, 32, 32, 32, 105, 102, 32, 40, 100, 97, 116, 97, 32, 43, 32, 115, 105,
        122, 101, 111, 102, 40, 115, 116, 114, 117, 99, 116, 32, 101, 116, 104, 104, 100, 114, 41,
        32, 62, 32, 100, 97, 116, 97, 95, 101, 110, 100, 41, 0, 32, 32, 32, 32, 115, 116, 114, 117,
        99, 116, 32, 101, 118, 101, 110, 116, 32, 42, 101, 32, 61, 32, 98, 112, 102, 95, 114, 105,
        110, 103, 98, 117, 102, 95, 114, 101, 115, 101, 114, 118, 101, 40, 38, 114, 98, 44, 32,
        115, 105, 122, 101, 111, 102, 40, 115, 116, 114, 117, 99, 116, 32, 101, 118, 101, 110, 116,
        41, 44, 32, 48, 41, 59, 0, 32, 32, 32, 32, 105, 102, 32, 40, 33, 101, 41, 0, 32, 32, 32,
        32, 115, 119, 105, 116, 99, 104, 32, 40, 98, 112, 102, 95, 110, 116, 111, 104, 115, 40,
        101, 116, 104, 45, 62, 104, 95, 112, 114, 111, 116, 111, 41, 41, 0, 32, 32, 32, 32, 32, 32,
        32, 32, 105, 102, 32, 40, 105, 112, 32, 43, 32, 115, 105, 122, 101, 111, 102, 40, 42, 105,
        112, 41, 32, 62, 32, 100, 97, 116, 97, 95, 101, 110, 100, 41, 0, 32, 32, 32, 32, 32, 32,
        32, 32, 101, 45, 62, 115, 97, 100, 100, 114, 46, 105, 112, 118, 52, 32, 61, 32, 98, 112,
        102, 95, 110, 116, 111, 104, 115, 40, 105, 112, 45, 62, 115, 97, 100, 100, 114, 41, 59, 0,
        32, 32, 32, 32, 32, 32, 32, 32, 101, 45, 62, 100, 97, 100, 100, 114, 46, 105, 112, 118, 52,
        32, 61, 32, 98, 112, 102, 95, 110, 116, 111, 104, 115, 40, 105, 112, 45, 62, 100, 97, 100,
        100, 114, 41, 59, 0, 32, 32, 32, 32, 32, 32, 32, 32, 105, 102, 32, 40, 105, 112, 118, 54,
        32, 43, 32, 115, 105, 122, 101, 111, 102, 40, 42, 105, 112, 118, 54, 41, 32, 62, 32, 100,
        97, 116, 97, 95, 101, 110, 100, 41, 0, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 101,
        45, 62, 115, 97, 100, 100, 114, 46, 105, 112, 118, 54, 91, 105, 93, 32, 61, 32, 98, 112,
        102, 95, 110, 116, 111, 104, 108, 40, 105, 112, 118, 54, 45, 62, 115, 97, 100, 100, 114,
        46, 105, 110, 54, 95, 117, 46, 117, 54, 95, 97, 100, 100, 114, 51, 50, 91, 105, 93, 41, 59,
        0, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 101, 45, 62, 100, 97, 100, 100, 114, 46,
        105, 112, 118, 54, 91, 105, 93, 32, 61, 32, 98, 112, 102, 95, 110, 116, 111, 104, 108, 40,
        105, 112, 118, 54, 45, 62, 100, 97, 100, 100, 114, 46, 105, 110, 54, 95, 117, 46, 117, 54,
        95, 97, 100, 100, 114, 51, 50, 91, 105, 93, 41, 59, 0, 32, 32, 32, 32, 101, 45, 62, 101,
        116, 104, 95, 112, 114, 111, 116, 111, 32, 61, 32, 98, 112, 102, 95, 110, 116, 111, 104,
        115, 40, 101, 116, 104, 45, 62, 104, 95, 112, 114, 111, 116, 111, 41, 59, 0, 32, 32, 32,
        32, 101, 45, 62, 116, 105, 109, 101, 115, 116, 97, 109, 112, 32, 61, 32, 98, 112, 102, 95,
        107, 116, 105, 109, 101, 95, 103, 101, 116, 95, 110, 115, 40, 41, 59, 0, 32, 32, 32, 32,
        101, 45, 62, 108, 101, 110, 103, 116, 104, 32, 61, 32, 100, 97, 116, 97, 95, 101, 110, 100,
        32, 45, 32, 100, 97, 116, 97, 59, 0, 32, 32, 32, 32, 98, 112, 102, 95, 114, 105, 110, 103,
        98, 117, 102, 95, 115, 117, 98, 109, 105, 116, 40, 101, 44, 32, 48, 41, 59, 0, 125, 0, 48,
        58, 49, 0, 48, 58, 48, 0, 48, 58, 50, 0, 48, 58, 57, 58, 48, 58, 48, 0, 48, 58, 57, 58, 48,
        58, 49, 0, 48, 58, 54, 58, 48, 58, 48, 58, 48, 58, 50, 0, 48, 58, 54, 58, 48, 58, 49, 58,
        48, 58, 50, 0, 108, 105, 99, 101, 110, 115, 101, 0, 46, 109, 97, 112, 115, 0, 120, 100,
        112, 0, 0, 0, 0, 159, 235, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 20, 0, 0, 0, 156, 2,
        0, 0, 176, 2, 0, 0, 172, 0, 0, 0, 8, 0, 0, 0, 25, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 14, 0,
        0, 0, 16, 0, 0, 0, 25, 5, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 215, 1, 0, 0, 0,
        132, 0, 0, 8, 0, 0, 0, 183, 1, 0, 0, 248, 1, 0, 0, 40, 144, 0, 0, 16, 0, 0, 0, 183, 1, 0,
        0, 41, 2, 0, 0, 36, 140, 0, 0, 24, 0, 0, 0, 183, 1, 0, 0, 82, 2, 0, 0, 14, 160, 0, 0, 40,
        0, 0, 0, 183, 1, 0, 0, 82, 2, 0, 0, 9, 160, 0, 0, 48, 0, 0, 0, 183, 1, 0, 0, 131, 2, 0, 0,
        23, 196, 0, 0, 104, 0, 0, 0, 183, 1, 0, 0, 204, 2, 0, 0, 9, 200, 0, 0, 120, 0, 0, 0, 183,
        1, 0, 0, 216, 2, 0, 0, 13, 212, 0, 0, 136, 0, 0, 0, 183, 1, 0, 0, 216, 2, 0, 0, 5, 212, 0,
        0, 152, 0, 0, 0, 183, 1, 0, 0, 253, 2, 0, 0, 16, 228, 0, 0, 168, 0, 0, 0, 183, 1, 0, 0,
        253, 2, 0, 0, 13, 228, 0, 0, 192, 0, 0, 0, 183, 1, 0, 0, 38, 3, 0, 0, 25, 240, 0, 0, 208,
        0, 0, 0, 183, 1, 0, 0, 38, 3, 0, 0, 23, 240, 0, 0, 216, 0, 0, 0, 183, 1, 0, 0, 84, 3, 0, 0,
        25, 244, 0, 0, 232, 0, 0, 0, 183, 1, 0, 0, 84, 3, 0, 0, 23, 244, 0, 0, 248, 0, 0, 0, 183,
        1, 0, 0, 130, 3, 0, 0, 18, 4, 1, 0, 8, 1, 0, 0, 183, 1, 0, 0, 130, 3, 0, 0, 13, 4, 1, 0,
        40, 1, 0, 0, 183, 1, 0, 0, 175, 3, 0, 0, 32, 24, 1, 0, 56, 1, 0, 0, 183, 1, 0, 0, 175, 3,
        0, 0, 30, 24, 1, 0, 72, 1, 0, 0, 183, 1, 0, 0, 249, 3, 0, 0, 32, 28, 1, 0, 88, 1, 0, 0,
        183, 1, 0, 0, 249, 3, 0, 0, 30, 28, 1, 0, 112, 1, 0, 0, 183, 1, 0, 0, 175, 3, 0, 0, 32, 24,
        1, 0, 128, 1, 0, 0, 183, 1, 0, 0, 175, 3, 0, 0, 30, 24, 1, 0, 144, 1, 0, 0, 183, 1, 0, 0,
        249, 3, 0, 0, 32, 28, 1, 0, 160, 1, 0, 0, 183, 1, 0, 0, 249, 3, 0, 0, 30, 28, 1, 0, 168, 1,
        0, 0, 183, 1, 0, 0, 175, 3, 0, 0, 32, 24, 1, 0, 184, 1, 0, 0, 183, 1, 0, 0, 175, 3, 0, 0,
        30, 24, 1, 0, 192, 1, 0, 0, 183, 1, 0, 0, 249, 3, 0, 0, 32, 28, 1, 0, 208, 1, 0, 0, 183, 1,
        0, 0, 249, 3, 0, 0, 30, 28, 1, 0, 216, 1, 0, 0, 183, 1, 0, 0, 175, 3, 0, 0, 32, 24, 1, 0,
        232, 1, 0, 0, 183, 1, 0, 0, 175, 3, 0, 0, 30, 24, 1, 0, 240, 1, 0, 0, 183, 1, 0, 0, 249, 3,
        0, 0, 32, 28, 1, 0, 0, 2, 0, 0, 183, 1, 0, 0, 249, 3, 0, 0, 30, 28, 1, 0, 24, 2, 0, 0, 183,
        1, 0, 0, 67, 4, 0, 0, 20, 72, 1, 0, 40, 2, 0, 0, 183, 1, 0, 0, 67, 4, 0, 0, 18, 72, 1, 0,
        48, 2, 0, 0, 183, 1, 0, 0, 111, 4, 0, 0, 20, 76, 1, 0, 56, 2, 0, 0, 183, 1, 0, 0, 111, 4,
        0, 0, 18, 76, 1, 0, 64, 2, 0, 0, 183, 1, 0, 0, 150, 4, 0, 0, 26, 80, 1, 0, 72, 2, 0, 0,
        183, 1, 0, 0, 150, 4, 0, 0, 15, 80, 1, 0, 80, 2, 0, 0, 183, 1, 0, 0, 183, 4, 0, 0, 5, 84,
        1, 0, 104, 2, 0, 0, 183, 1, 0, 0, 213, 4, 0, 0, 1, 96, 1, 0, 16, 0, 0, 0, 25, 5, 0, 0, 10,
        0, 0, 0, 8, 0, 0, 0, 10, 0, 0, 0, 215, 4, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 10, 0, 0, 0, 219,
        4, 0, 0, 0, 0, 0, 0, 112, 0, 0, 0, 15, 0, 0, 0, 223, 4, 0, 0, 0, 0, 0, 0, 120, 0, 0, 0, 15,
        0, 0, 0, 223, 4, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 21, 0, 0, 0, 227, 4, 0, 0, 0, 0, 0, 0,
        216, 0, 0, 0, 21, 0, 0, 0, 235, 4, 0, 0, 0, 0, 0, 0, 32, 1, 0, 0, 27, 0, 0, 0, 243, 4, 0,
        0, 0, 0, 0, 0, 40, 1, 0, 0, 27, 0, 0, 0, 243, 4, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 27, 0, 0,
        0, 255, 4, 0, 0, 0, 0, 0, 0, 72, 1, 0, 0, 27, 0, 0, 0, 255, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64,
        0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 216, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 8, 0,
        0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 136, 1, 0, 0, 0, 0, 0, 0, 120, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 1, 0, 0,
        0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 4, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 86, 0, 0,
        0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 4, 0, 0, 0, 0, 0, 0,
        16, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0,
        0, 0, 94, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 4, 0, 0,
        0, 0, 0, 0, 149, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 99, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        200, 13, 0, 0, 0, 0, 0, 0, 124, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}
