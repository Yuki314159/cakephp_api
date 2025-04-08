<?php

declare(strict_types=1);

namespace App\Controller;

use App\Controller\AppController;
use Firebase\JWT\JWT;
use Cake\ORM\TableRegistry;
use Cake\Http\Exception\UnauthorizedException;
use Cake\Core\Configure;

use Cake\Log\Log;

/**
 * Users Controller
 */
class UsersController extends AppController
{
    public function beforeFilter(\Cake\Event\EventInterface $event)
    {
        parent::beforeFilter($event);
    }

    public function initialize(): void
    {
        parent::initialize();
    }

    // ユーザー一覧
    public function index()
    {
        $query = $this->Users->find();
        $users = $this->paginate($query);
        $this->set(compact('users'));
    }

    // ユーザー詳細
    public function view($id = null)
    {
        $user = $this->Users->get($id);
        $this->set(compact('user'));
    }

    // ユーザーログイン
    public function login()
    {
        //Log::info(print_r($this->request->getData(), true));

        if ($this->request->is('post')) {
            $result = $this->Authentication->getResult();

            if (!$result->isValid()) {
                return $this->response->withStatus(400)
                    ->withType('application/json')
                    ->withStringBody(json_encode(['error' => 'メールアドレスもしくはパスワードが間違っています。']));
            }

            // ユーザー情報を取得
            $user = $this->Authentication->getIdentity();

            $key = Configure::read('Security.jwt_secret'); // JWT秘密鍵を取得
            $payload = [
                'sub' => $user->get('id'),
                'email' => $user->get('email'),
                'exp' => time() + 3600, // 1時間後にトークン失効
            ];

            $token = JWT::encode($payload, $key, 'HS256');

            return $this->response->withType('application/json')
                ->withStringBody(json_encode(['token' => $token]));
        }

        // POST以外でアクセスされた場合のレスポンス（任意）
        return $this->response->withStatus(401)
            ->withType('application/json')
            ->withStringBody(json_encode(['error' => '予期せぬエラーが発生しました。']));
    }

    // ユーザー登録
    public function register()
    {
        //Log::info(print_r($this->request->getData(), true));

        if ($this->request->is('post')) {
            $usersTable = TableRegistry::getTableLocator()->get('Users');
            $user = $usersTable->newEntity($this->request->getData());

            if ($usersTable->save($user)) {
                return $this->response->withType('application/json')
                    ->withStringBody(json_encode(['message' => '登録しました！']));
            }

            // 保存に失敗した場合のエラーをログに出力
            Log::error('User registration failed. Errors: ' . print_r($user->getErrors(), true));

            return $this->response->withStatus(400)
                ->withType('application/json')
                ->withStringBody(json_encode([
                    'error' => '登録に失敗しました。',
                    'details' => $user->getErrors(),
                ]));
        }

        // POST以外でアクセスされた場合のレスポンス（任意）
        return $this->response->withStatus(401)
            ->withType('application/json')
            ->withStringBody(json_encode(['error' => 'こちらの内容では登録できません。']));
    }

    public function callback()
    {
        $result = $this->Authentication->getResult();

        if (!$result->isValid()) {
            return $this->response->withStatus(401)
                ->withType('application/json')
                ->withStringBody(json_encode(['error' => 'トークンが無効か期限切れです']));
        }

        $user = $this->Authentication->getIdentity();
        //Log::info(print_r($user, true));

        return $this->response->withType('application/json')
            ->withStringBody(json_encode([
                'message' => '認証成功',
                'user' => [
                    'id' => $user->sub,
                    'email' => $user->email
                ]
            ]));
    }
}
