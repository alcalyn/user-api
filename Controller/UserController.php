<?php

namespace Alcalyn\UserApi\Controller;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Symfony\Component\HttpFoundation\Request;
use Alcalyn\UserApi\Exception\UserNotFoundException;
use Alcalyn\UserApi\Exception\UserAlreadyExistsException;
use Alcalyn\UserApi\Model\User;
use Alcalyn\UserApi\Api\ApiInterface;

class UserController
{
    /**
     * @var ApiInterface
     */
    protected $api;

    /**
     * Authenticated user
     *
     * @var User|null
     */
    protected $loggedUser;

    /**
     * @param ApiInterface $api
     */
    public function __construct(ApiInterface $api)
    {
        $this->api = $api;
    }

    /**

     * @param User $loggedUser
     *
     * @return UserController
     */
    public function setLoggedUser(User $loggedUser)
    {
        $this->loggedUser = $loggedUser;

        return $this;
    }

    /**
     * @return User[]
     */
    public function getUsers()
    {
        return $this->api->getUsers();
    }

    /**
     * @return User
     */
    public function getUser($username)
    {
        $user = $this->api->getUser($username);

        if (null === $user) {
            throw new NotFoundHttpException('User '.$username.' not found.');
        }

        return $user;
    }

    /**
     * Create or update an User.
     * Should be run by logged user or admin.
     *
     * @param Request $request
     *
     * @return User created user.
     */
    public function postUser(Request $request)
    {
        $username = $request->request->get('username');
        $password = $request->request->get('password');

        if (empty($username)) {
            throw new BadRequestHttpException('Username cannot be empty.');
        }

        if (empty($password)) {
            throw new BadRequestHttpException('Password cannot be empty.');
        }

        try {
            $user = $this->api->createUser($username, $password);
        } catch (UserAlreadyExistsException $e) {
            throw new ConflictHttpException('An user with username "'.$username.'" already exists.', $e);
        }

        return $user;
    }

    /**
     * Update player password.
     * Needs to be logged.
     *
     * @param Request $request
     *
     * @return bool
     *
     * @throws HttpException if no logged user.
     */
    public function changePassword(Request $request)
    {
        $this->mustBeLogged();

        $newPassword = $request->request->get('new_password');

        $this->api->changePassword($this->loggedUser, $newPassword);

        return true;
    }

    /**
     * @param string $emailVerificationToken
     *
     * @return bool
     *
     * @throws BadRequestHttpException on invalid email verification token
     */
    public function verifyEmail($emailVerificationToken)
    {
        $success = $this->api->verifyEmail($emailVerificationToken);

        if (!$success) {
            throw new BadRequestHttpException('Invalid email verification token.');
        }

        return true;
    }

    /**
     * Delete an user.
     * Should be run by logged user or admin.
     *
     * @param string $username
     *
     * @return bool
     *
     * @throws NotFoundHttpException if user does not exists.
     */
    public function deleteUser($username)
    {
        try {
            $this->api->deleteUser($username);
        } catch (UserNotFoundException $e) {
            throw new NotFoundHttpException('Delete action failed: user '.$username.' not found.', $e);
        }

        return true;
    }

    /**
     * @return int
     */
    public function countUsers()
    {
        return $this->api->countUsers();
    }

    /**
     * Returns authenticated user.
     *
     * @return User
     *
     * @throws HttpException if no logged user.
     */
    public function authMe()
    {
        $this->mustBeLogged();

        return $this->loggedUser;
    }

    /**
     * @throws HttpException
     */
    private function mustBeLogged()
    {
        if (null === $this->loggedUser) {
            throw new HttpException(401);
        }
    }
}
