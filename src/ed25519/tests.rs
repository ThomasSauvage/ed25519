use std::{
    fs,
    io::{self, BufRead},
};

use crate::ed25519::{sign, verify};

use super::{keygen, points::Point, test_utils};

use num_bigint::BigInt;
use num_traits::Euclid;

#[test]
fn test_point() {
    let a = Point::new_from_i32(1, 2, 3, 4);

    let b = Point::new_from_i32(5, 6, 7, 8);

    let _ = &a + &b;
    let _ = &a * &BigInt::from(2);

    let c = Point::new_from_i32(1, 2, 3, 444);

    // Uses == equality, which doesn't take into account the t coordinate
    assert_eq!(a, c);
}

#[test]
fn euclidian_reminder() {
    let a = BigInt::from(-43);

    assert_eq!(&a % 4, BigInt::from(-3)); // Negative !!
    assert_eq!(a.rem_euclid(&BigInt::from(4)), BigInt::from(1)); // Positive !!
}

#[test]
fn ed25519_private_to_public_key_1() {
    let private_key = test_utils::hex_decode_32(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );

    let expected_public_key = test_utils::hex_decode_32(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );

    let public_key = keygen::private_to_public_key(private_key);

    assert_eq!(public_key, expected_public_key);
}

#[test]
fn ed25519_private_to_public_key_2() {
    let private_key = test_utils::hex_decode_32(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    );

    let expected_public_key = test_utils::hex_decode_32(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );

    let public_key = keygen::private_to_public_key(private_key);

    assert_eq!(public_key, expected_public_key);
}

#[test]
fn ed25519_private_to_public_key_3() {
    let private_key = test_utils::hex_decode_32(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    );

    let expected_public_key = test_utils::hex_decode_32(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    );

    let public_key = keygen::private_to_public_key(private_key);

    assert_eq!(public_key, expected_public_key);
}

#[test]
fn ed25519_private_to_public_key_4() {
    let private_key = test_utils::hex_decode_32(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    );

    let expected_public_key = test_utils::hex_decode_32(
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    );

    let public_key = keygen::private_to_public_key(private_key);

    assert_eq!(public_key, expected_public_key);
}

#[test]
fn ed25519_private_to_public_key_5() {
    let private_key = test_utils::hex_decode_32(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    );

    let expected_public_key = test_utils::hex_decode_32(
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    );

    let public_key = keygen::private_to_public_key(private_key);

    assert_eq!(public_key, expected_public_key);
}

#[test]
fn ed25519_sign_1() {
    let private_key = test_utils::hex_decode_32(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );

    let expected_sign = test_utils::hex_decode_64(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let msg = test_utils::hex_decode_msg("");

    let sign = sign::sign(&private_key, &msg);

    assert_eq!(sign, expected_sign);

    let public_key = keygen::private_to_public_key(private_key);

    assert!(verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_sign_2() {
    let private_key = test_utils::hex_decode_32(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    );

    let expected_sign = test_utils::hex_decode_64(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );

    let msg = test_utils::hex_decode_msg("72");

    let sign = sign::sign(&private_key, &msg);

    assert_eq!(sign, expected_sign);

    let public_key = keygen::private_to_public_key(private_key);

    assert!(verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_sign_3() {
    let private_key = test_utils::hex_decode_32(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    );

    let expected_sign = test_utils::hex_decode_64(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    );

    let msg = test_utils::hex_decode_msg("af82");

    let sign = sign::sign(&private_key, &msg);

    assert_eq!(sign, expected_sign);

    let public_key = keygen::private_to_public_key(private_key);

    assert!(verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_sign_4() {
    let private_key = test_utils::hex_decode_32(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    );

    let expected_sign = test_utils::hex_decode_64(
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    );

    let msg = test_utils::hex_decode_msg("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");

    let sign = sign::sign(&private_key, &msg);

    assert_eq!(sign, expected_sign);

    let public_key = keygen::private_to_public_key(private_key);

    assert!(verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_sign_5() {
    let private_key = test_utils::hex_decode_32(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    );

    let expected_sign = test_utils::hex_decode_64(
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    );

    let msg = test_utils::hex_decode_msg("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    let sign = sign::sign(&private_key, &msg);

    assert_eq!(sign, expected_sign);

    let public_key = keygen::private_to_public_key(private_key);

    assert!(verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_msg_sign_fail_2() {
    let private_key = test_utils::hex_decode_32(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    );

    let mut msg = test_utils::hex_decode_msg("72");

    let public_key = keygen::private_to_public_key(private_key);
    let sign = sign::sign(&private_key, &msg);

    msg[0] = 42u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_msg_sign_fail_3() {
    let private_key = test_utils::hex_decode_32(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    );

    let mut msg = test_utils::hex_decode_msg("af82");

    let public_key = keygen::private_to_public_key(private_key);
    let sign = sign::sign(&private_key, &msg);

    msg[0] = 2u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_msg_sign_fail_4() {
    let private_key = test_utils::hex_decode_32(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    );

    let mut msg = test_utils::hex_decode_msg("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");

    let public_key = keygen::private_to_public_key(private_key);
    let sign = sign::sign(&private_key, &msg);

    msg[77] = 123u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_msg_sign_fail_5() {
    let private_key = test_utils::hex_decode_32(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    );

    let mut msg = test_utils::hex_decode_msg("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    let public_key = keygen::private_to_public_key(private_key);
    let sign = sign::sign(&private_key, &msg);

    msg[33] = 218u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_sign_sign_fail_1() {
    let private_key = test_utils::hex_decode_32(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );

    let msg = test_utils::hex_decode_msg("");

    let public_key = keygen::private_to_public_key(private_key);
    let mut sign = sign::sign(&private_key, &msg);

    sign[0] = 42u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_sign_sign_fail_2() {
    let private_key = test_utils::hex_decode_32(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    );

    let msg = test_utils::hex_decode_msg("72");

    let public_key = keygen::private_to_public_key(private_key);
    let mut sign = sign::sign(&private_key, &msg);

    sign[34] = 47u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_sign_sign_fail_3() {
    let private_key = test_utils::hex_decode_32(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    );

    let msg = test_utils::hex_decode_msg("af82");

    let public_key = keygen::private_to_public_key(private_key);
    let mut sign = sign::sign(&private_key, &msg);

    sign[63] = 99u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_sign_sign_fail_4() {
    let private_key = test_utils::hex_decode_32(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    );

    let msg = test_utils::hex_decode_msg("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");

    let public_key = keygen::private_to_public_key(private_key);
    let mut sign = sign::sign(&private_key, &msg);

    sign[10] = 123u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_modified_sign_sign_fail_5() {
    let private_key = test_utils::hex_decode_32(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    );

    let msg = test_utils::hex_decode_msg("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    let public_key = keygen::private_to_public_key(private_key);
    let mut sign = sign::sign(&private_key, &msg);

    sign[50] = 218u8;

    assert!(!verify::verify(&public_key, &msg, &sign));
}

#[test]
fn ed25519_all_test_vectors() {
    let file =
        fs::File::open("examples/test-vectors.txt").expect("Could not open test vectors file");

    let reader = io::BufReader::new(file);

    let mut i = 0;
    for line in reader.lines() {
        let line = line.unwrap();

        let splitted: Vec<&str> = line.split(':').collect();

        let private_key = test_utils::hex_decode_32(&splitted[0][..64]);
        let public_key = test_utils::hex_decode_32(splitted[1]);
        let msg = hex::decode(splitted[2]).unwrap();
        let expected_signature_str = &splitted[3][..(splitted[3].len() - splitted[2].len())];
        let expected_signature = test_utils::hex_decode_64(expected_signature_str);

        let signature = sign(&private_key, &msg);

        assert_eq!(signature, expected_signature);
        assert!(verify(&public_key, &msg, &signature));

        // Modify the message/signature and check if it works

        let msg_length = msg.len();

        if msg_length != 0 {
            let mut modified_msg = msg.clone();
            modified_msg[(4236233 * i) % msg_length] ^= 1 + ((2153465 * i) % 8) as u8;
            assert!(!verify(&public_key, &modified_msg, &signature));
        };

        let mut modified_signature = signature.clone();
        modified_signature[(37423457 * i) % 64] ^= 1 + ((964854563 * i) % 8) as u8;

        assert!(!verify(&public_key, &msg, &modified_signature));

        i += 1;
    }
}
