<?php

namespace App\Http\Requests\User;

use Illuminate\Foundation\Http\FormRequest;

class UserCheckin extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'value' => 'required|integer|min:1|max:1000',
            'unit' => 'required|in:MB,GB'
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
            'value.required' => '请输入数值',
            'value.integer' => '数值必须是整数',
            'value.min' => '数值不能小于1',
            'value.max' => '数值不能大于1000',
            'unit.required' => '请输入单位',
            'unit.in' => '单位必须是 MB 或 GB'
        ];
    }

    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }
}