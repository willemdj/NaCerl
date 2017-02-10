%% License: MIT
%% 
%% Copyright (c) 2013 Tony Garnock-Jones tonygarnockjones@gmail.com
%% 
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%% 
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.

-module(nacerl_nif).

-export([randombytes/1,
         hash/1,
         box_keypair/0,
         box_NONCEBYTES/0,
         box_ZEROBYTES/0,
         box_BOXZEROBYTES/0,
         box_padded/4,
         box_open_padded/4,
         secretbox_padded/3,
         secretbox_open_padded/3,
         secretbox_ZEROBYTES/0,
         secretbox_BOXZEROBYTES/0,
         secretbox_NONCEBYTES/0,
         secretbox_KEYBYTES/0
        ]).

-on_load(init/0).

init() -> erlang:load_nif(filename:join(nacerl_app:priv_dir(), ?MODULE), 0).

randombytes(_Count) -> erlang:nif_error(not_loaded).
hash(_Bytes) -> erlang:nif_error(not_loaded).
box_keypair() -> erlang:nif_error(not_loaded).
box_NONCEBYTES() -> erlang:nif_error(not_loaded).
box_ZEROBYTES() -> erlang:nif_error(not_loaded).
box_BOXZEROBYTES() -> erlang:nif_error(not_loaded).
box_padded(_PaddedMsg, _Nonce, _Pk, _Sk) -> erlang:nif_error(not_loaded).
box_open_padded(_PaddedCipher, _Nonce, _Pk, _Sk) -> erlang:nif_error(not_loaded).
secretbox_padded(_Msg, _Nonce, _Key) -> erlang:nif_error(not_loaded).
secretbox_open_padded(_Ciphertext, _Nonce, _Key) -> erlang:nif_error(not_loaded).
secretbox_ZEROBYTES() -> erlang:nif_error(not_loaded).
secretbox_BOXZEROBYTES() -> erlang:nif_error(not_loaded).
secretbox_NONCEBYTES() -> erlang:nif_error(not_loaded).
secretbox_KEYBYTES() -> erlang:nif_error(not_loaded).
