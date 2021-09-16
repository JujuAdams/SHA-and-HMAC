/// @param string
/// @param [returnString=true]

function string_sha256(_string, _return_string = true)
{
    var _buffer = buffer_create(string_byte_length(_string), buffer_fixed, 1);
    buffer_write(_buffer, buffer_text, _string);
    return buffer_sha256(_buffer, undefined, undefined, true, _return_string);
}