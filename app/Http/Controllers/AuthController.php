<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
			return response()->json([
                'code'    => 400,
                'message' => $validator->errors(),
                'data'    => []
            ], 400);
		}

        $getUser = User::where('username', $request->username)->count();
        if (!$getUser) {
            return response()->json([
                'code'    => 500,
                'message' => 'User not registered',
                'data'    => []
            ], 500);
        }

        $credentials = $request->only('username', 'password');
        $token = Auth::guard('api')->attempt($credentials);
        
        if (!$token) {
            return response()->json([
                'code'    => 400,
                'message' => 'Username or password incorrect',
                'data'    => []
            ], 400);
        }

        $data = [
            'token' => $token,
            'user'  => Auth::user()
        ];

        return response()->json([
            'code'    => 200,
            'message' => 'Success',
            'data'    => $data
        ]);
    }

    public function signup(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|min:2',
            'fullname' => 'required',
            'password' => 'required|min:5',
        ]);

        if ($validator->fails()) {
			return response()->json([
                'code'    => 400,
                'message' => $validator->errors(),
                'data'    => []
            ], 400);
		}

        $usernameUnique = User::where('username', $request->username)->count();
        if ($usernameUnique) {
            return response()->json([
                'code'    => 409,
                'message' => 'Username already exists',
                'data'    => []
            ], 409);
        }

        try {
            User::create([
                'username' => $request->username,
                'fullname' => $request->fullname,
                'password' => Hash::make($request->password),
            ]);

            $response = [
                'code'    => 200,
                'message' => 'Success',
                'data'    => []
            ];
        } catch (\Throwable $th) {
            $response = [
                'code'    => 200,
                'message' => 'Success',
                'data'    => $th->getMessage()
            ];
        }

        return response()->json($response, $response['code']);
    }

    public function userList(Request $request)
    {
        $this->middleware('jwt.verify');

        $limit = $request->limit ? $request->limit : 10;
        $page  = $request->page && $request->page > 0 ? $request->page : 1;
        $skip  = ($page - 1) * $limit;

        $getUser = User::all()->slice($skip);
        if (empty($getUser)) {
            return response()->json([
                'code'    => 404,
                'message' => 'Data not found',
                'data'    => []
            ], 404);
        }

        $response = [
            'code'    => 200,
            'message' => 'Success',
            'data'    => $getUser,
            'meta'    => [
				'total'      => (int) count($getUser),
				'limit'      => (int) $limit,
				'page'       => (int) $page,
				'total_page' => (int) ceil(count($getUser) / $limit)
			]
        ];

        return response()->json($response, 200);
    }
}
