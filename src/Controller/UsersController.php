<?php

declare(strict_types=1);

namespace App\Controller;

use App\Controller\AppController;
use Firebase\JWT\JWT;
use Cake\ORM\TableRegistry;
use Cake\Http\Exception\UnauthorizedException;
use Cake\Core\Configure;

/**
 * Users Controller
 */
class UsersController extends AppController
{
    public function initialize(): void
    {
        parent::initialize();
        $this->Authentication->allowUnauthenticated(['login', 'register']);
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
        $this->request->allowMethod(['post']);
        $result = $this->Authentication->getResult();

        if (!$result->isValid()) {
            throw new UnauthorizedException('Invalid email or password');
        }

        // ユーザー情報を取得
        $user = $this->Authentication->getIdentity();

        $key = Configure::read('Security.jwt_secret'); // JWT秘密鍵を取得
        $payload = [
            'sub' => $user->get('id'),
            'exp' => time() + 3600, // 1時間後にトークン失効
        ];

        $token = JWT::encode($payload, $key, 'HS256');

        return $this->response->withType('application/json')
            ->withStringBody(json_encode(['token' => $token]));
    }

    // ユーザー登録
    public function register()
    {
        $this->request->allowMethod(['post']);
        $usersTable = TableRegistry::getTableLocator()->get('Users');
        $user = $usersTable->newEntity($this->request->getData());

        if ($usersTable->save($user)) {
            return $this->response->withType('application/json')
                ->withStringBody(json_encode(['message' => 'User registered successfully']));
        }

        return $this->response->withStatus(400)
            ->withType('application/json')
            ->withStringBody(json_encode([
                'error' => 'User registration failed',
                'details' => $user->getErrors(),
            ]));
    }
}
