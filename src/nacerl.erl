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

-module(nacerl).

-export([randombytes/1,
         box_keypair/0,
         box/4,
         box_open/4]).


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

randombytes(Count) -> nacerl_nif:randombytes(Count).

box_keypair() -> 
    {nacerl_box_keypair, Public, Secret} =  nacerl_nif:box_keypair(),
    #{public => Public, secret => Secret}.

box(Msg, Nonce, Pk, Sk) ->
    nacerl_nif:box_padded([binary:copy(<<0>>, 
                           nacerl_nif:box_ZEROBYTES()), Msg], Nonce, Pk, Sk).

box_open(Ciph, Nonce, Pk, Sk) ->
    case nacerl_nif:box_open_padded([binary:copy(<<0>>, nacerl_nif:box_BOXZEROBYTES()), Ciph],
                                  Nonce, Pk, Sk) of
        {error, Error} ->
            {error, Error};
        Bin when is_binary(Bin) ->
            {ok, Bin}
    end.

-ifdef(TEST).

%% Super weird that this isn't in the standard library. Perhaps it is
%% and I've overlooked or forgotten about it.
b2h(B) -> lists:flatten([io_lib:format("~2.16.0b",[N]) || <<N>> <= B]).

basic_test() ->
    ?assertEqual(<<>>, randombytes(0)).

box_keypair_test() ->
    #{public := PK, secret := SK} = box_keypair(),
    ?assertEqual(true, is_binary(PK)),
    ?assertEqual(true, is_binary(SK)).

pk1() -> <<16#de1042928b74e9f96cf3f3e290c16cb4eba9c696e9a1e15c7f4d0514ddce1154:256>>.
sk1() -> <<16#d54ff4b666a43070ab20937a92c49ecf65503583f8942350fc197c5023b015c3:256>>.

box_test() ->
    Nonce = <<16#065114ca5a687e0544a88e6fc757b30afc70a0355854fd54:192>>,
    Msg = <<"hello">>,
    Boxed = box(Msg, Nonce, pk1(), sk1()),
    ?assertEqual("3bc95b7983622e8afb763723703e17c6739be9c316", b2h(Boxed)),
    {ok, Unboxed} = box_open(Boxed, Nonce, pk1(), sk1()),
    ?assertEqual(<<"hello">>, Unboxed).

-endif.
