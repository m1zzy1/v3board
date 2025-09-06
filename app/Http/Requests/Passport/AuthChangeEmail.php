<?php

namespace App\Http\Requests\Passport;

use Illuminate\Foundation\Http\FormRequest;

class AuthChangeEmail extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'new_email' => 'required|email:strict|unique:v2_user,email', // 新邮箱必须是有效的邮箱且未被其他用户使用 (修正表名为 v2_user)
            'email_code' => 'nullable|string|max:32' // 验证码，只有在开启邮箱验证时才是必需的
        ];
    }

    /**
     * Get custom messages for validator errors.
     *
     * @return array
     */
    public function messages()
    {
        return [
            'new_email.required' => '新邮箱地址不能为空',
            'new_email.email' => '请输入有效的邮箱地址',
            'new_email.unique' => '该邮箱地址已被其他用户使用，请更换',
            'email_code.string' => '验证码格式不正确',
            'email_code.max' => '验证码长度过长'
        ];
    }

    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true; // 假设所有经过 auth:api 中间件的用户都有权限
    }
}