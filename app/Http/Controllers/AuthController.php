<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // validate
        $validated = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);
        // create user
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password'])
        ]);
        // issue token & send it with user in response
        return response([
            'user' => $user,
            'token' => $user->createToken('myapptoken')->plainTextToken
        ], 201);
    }

    public function login(Request $request)
    {
        // validate
        $validated = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string'
        ]);
        // check if email in db
        $user = User::where('email', $validated['email'])->first();
        // check if password is correct
        if (!$user || !Hash::check($validated['password'], $user->password)) {
            return response(['message' => 'bad credentials'], 401);
        }
        // issue a token & send it with user
        return response([
            'user' => $user,
            'token' => $user->createToken('myapptoken')->plainTextToken
        ], 201);
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()-delete();
        return ['message' => 'logged out successfully'];
    }
}
