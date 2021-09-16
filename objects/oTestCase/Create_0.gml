////Test cases from https://www.di-mgt.com.au/sha_testvectors.html
show_debug_message("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad == " + string_sha256("abc"));
show_debug_message("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 == " + string_sha256(""));
show_debug_message("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 == " + string_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
show_debug_message("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1 == " + string_sha256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));

//One million "a"s
var _t = get_timer();
var _buffer = buffer_create(1000000, buffer_fixed, 1);
buffer_fill(_buffer, 0, buffer_u8, ord("a"), buffer_get_size(_buffer));
var _string = buffer_read(_buffer, buffer_text);

show_debug_message("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 == " + string_sha256(_string));
show_debug_message("Took " + string(get_timer() - _t) + "us for " + string(string_byte_length(_string)) + " bytes");

show_debug_message("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9 = " + hmac_sha1("key", "The quick brown fox jumps over the lazy dog"));
show_debug_message("11db7e3f42589f4595aba8caeb282d65c8200ab2 = " + hmac_sha1("woah this is a really long key that we have to use to test HMAC fully", "The quick brown fox jumps over the lazy dog"));

show_debug_message("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8 = " + hmac_sha256("key", "The quick brown fox jumps over the lazy dog"));
show_debug_message("ed9370825ec8fd46b497ffc9c1eb8ecab3cde50fa61c2d55a1aed002cdb6be4f = " + hmac_sha256("woah this is a really long key that we have to use to test HMAC fully", "The quick brown fox jumps over the lazy dog"));

show_debug_message("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043 = " + string_sha512("hello"));
show_debug_message("b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a = " + hmac_sha512("key", "The quick brown fox jumps over the lazy dog"));
show_debug_message("39c4ce122b04a5fdb38b685502cef99937dfeb73a9a9cf3a85754aa1dee6e8bd03c4ac862acaed6f438b82504737fe4f8944b98f170bafb0daebd1cd89039fe1 = " + hmac_sha512("woah this is a really long key that we have to use to test HMAC fully", "The quick brown fox jumps over the lazy dog"));
