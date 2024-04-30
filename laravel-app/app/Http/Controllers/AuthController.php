<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Exceptions\HttpResponseException;


class AuthController extends Controller
{
    public function register(Request $request) {

        $request->validate([
            'name'=> 'required|string|max:255',
            'email'=> 'required|string|email|max:255|unique:users',
            'password'=> 'required|string|min:8',
        ]);


        $CheckEmail = User::where('email', $request->email)->first();
        if ($CheckEmail) {
            throw new HttpResponseException(
                response()->json(['errors' => ['email' => ['This email is already registered.']]], 422)
            );
        }
    
        $user = User::create([
            'name' => $request->name,
            'email'=> $request->email,
            'password' => Hash::make($request->password),
            'role' => "users"
        ]);

        return response()->json(['user'=> $user],201);
    }

    public function login(Request $request) {

        if(!Auth::attempt($request->only('email','password'))){
            return response()->json(['message'=> 'Invalid login details'],401);
        }

        $user = $request->user();

        if ($user->role === 'users') {
            $token = $user->createToken('authToken', ['post', 'update'])->plainTextToken;
        } else {
            $token = $user->createToken('authToken',['*'])->plainTextToken;
        }

        $cookie = cookie('jwt', $token, 60*24); //30 day

        return response()->json(['user'=> $user,'token'=> $token ],201)->withCookie($cookie);
    }
    
    public function user() 
    {

        return Auth::user();
    }
    public function logout() {

        $cookie = Cookie::forget('jwt');

        return response(['message' => 'Success'])->withCookie($cookie); 
    }
}
