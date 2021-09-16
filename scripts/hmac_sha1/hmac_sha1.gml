/// @jujuadams 2021-09-16
///
/// @param keyString
/// @param message

function hmac_sha1(_key, _message)
{
    var _block_size  = 64;
    var _return_size = 20;
    
    var _inner_pad_buffer = buffer_create(_block_size + string_byte_length(_message), buffer_fixed, 1);
    var _outer_pad_buffer = buffer_create(_block_size + _return_size, buffer_fixed, 1);
    
    var _key_length = string_byte_length(_key);
    if (_key_length > _block_size)
    {
        //If the key is longer than the block size, we hash the key and use that instead
        var _hash = sha1_string_utf8(_key);
        
        //Add the (hashed) key to the inner and outer pad buffers, XOR'd as necessary
        var _n = 1;
        repeat(_return_size)
        {
            //We need to decode the returned hex string into integers to write to the padding buffers
            var _ord_msf = string_byte_at(_hash, _n  );
            var _ord_lsf = string_byte_at(_hash, _n+1);
            var _value = (((_ord_msf >= 97)? (_ord_msf - 87) : (_ord_msf - 48)) << 4) | ((_ord_lsf >= 97)? (_ord_lsf - 87) : (_ord_lsf - 48));
            
            buffer_write(_inner_pad_buffer, buffer_u8, 0x36 ^ _value);
            buffer_write(_outer_pad_buffer, buffer_u8, 0x5c ^ _value);
            
            _n += 2;
        }
        
        //Set the key length to the return size for the benefit of figuring out how much padding to add
        _key_length = _return_size;
    }
    else
    {
        //If the key is smaller than the block size, just use the key
        var _n = 1;
        repeat(_key_length)
        {
            var _value = string_byte_at(_key, _n);
            buffer_write(_inner_pad_buffer, buffer_u8, $36 ^ _value);
            buffer_write(_outer_pad_buffer, buffer_u8, $5C ^ _value);
            _n++;
        }
    }
    
    //Pad out the rest too!
    buffer_fill(_inner_pad_buffer, _key_length, buffer_u8, 0x36, _block_size - _key_length);
    buffer_fill(_outer_pad_buffer, _key_length, buffer_u8, 0x5c, _block_size - _key_length);
    buffer_seek(_inner_pad_buffer, buffer_seek_start, _block_size);
    buffer_seek(_outer_pad_buffer, buffer_seek_start, _block_size);
    
    //Append the message to the inner padding, and hash the whole lot
    buffer_write(_inner_pad_buffer, buffer_text, _message);
    var _hash = buffer_sha1(_inner_pad_buffer, 0, buffer_tell(_inner_pad_buffer));
    
    //Turn the inner hash into bytes and append that to the outer pad
    var n = 1;
    repeat(_return_size)
    {
        var _ord_msf = string_byte_at(_hash, n  );
        var _ord_lsf = string_byte_at(_hash, n+1);
        buffer_write(_outer_pad_buffer, buffer_u8, (((_ord_msf >= 97)? (_ord_msf - 87) : (_ord_msf - 48)) << 4) | ((_ord_lsf >= 97)? (_ord_lsf - 87) : (_ord_lsf - 48)));
        n += 2;
    }
    
    //And finally hash the outer padding too
    var _result = buffer_sha1(_outer_pad_buffer, 0, buffer_tell(_outer_pad_buffer));
    
    buffer_delete(_inner_pad_buffer);
    buffer_delete(_outer_pad_buffer);
    
    return _result;
}