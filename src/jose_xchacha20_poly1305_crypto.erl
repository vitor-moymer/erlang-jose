%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2019, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  14 Sep 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_xchacha20_poly1305_crypto).

-behaviour(jose_xchacha20_poly1305).

%% jose_xchacha20_poly1305 callbacks
-export([decrypt/5]).
-export([encrypt/4]).
-export([authenticate/3]).
-export([verify/4]).

%%====================================================================
%% jose_xchacha20_poly1305 callbacks
%%====================================================================

decrypt(CipherText, CipherTag, AAD, IV, CEK) ->
	crypto:crypto_one_time_aead(xchacha20_poly1305, CEK, IV,CipherText,AAD, CipherTag, false).

encrypt(PlainText, AAD, IV, CEK) ->
	crypto:crypto_one_time_aead(xchacha20_poly1305, CEK, IV,  PlainText, AAD, true).

authenticate(Message, Key, Nonce) ->
	jose_jwa_xchacha20_poly1305:authenticate(Message, Key, Nonce).

verify(MAC, Message, Key, Nonce) ->
	jose_jwa_xchacha20_poly1305:verify(MAC, Message, Key, Nonce).
