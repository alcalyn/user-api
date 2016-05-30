<?php

namespace Alcalyn\UserApi\Controller;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Alcalyn\SerializableApiResponse\ApiResponse;
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
     * @return self
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
        return new ApiResponse($this->api->getUsers());
    }

    /**
     * @return ApiResponse
     */
    public function getUser($username)
    {
        $user = $this->api->getUser($username);

        if (null === $user) {
            throw new NotFoundHttpException('User '.$username.' not found.');
        }

        return new ApiResponse($user);
    }

    /**
     * Create or update an User.
     * Should be run by logged user or admin.
     *
     * @param Request $request
     *
     * @return ApiResponse
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

        return new ApiResponse($user, Response::HTTP_CREATED);
    }

    /**
     * Update player password.
     * Needs to be logged.
     *
     * @param Request $request
     *
     * @return ApiResponse
     *
     * @throws HttpException if no logged user.
     */
    public function changePassword(Request $request)
    {
        $this->mustBeLogged();

        $newPassword = $request->request->get('new_password');

        $this->api->changePassword($this->loggedUser, $newPassword);

        return new ApiResponse(true);
    }

    /**
     * @param string $emailVerificationToken
     *
     * @return ApiResponse
     *
     * @throws BadRequestHttpException on invalid email verification token
     */
    public function verifyEmail($emailVerificationToken)
    {
        $success = $this->api->verifyEmail($emailVerificationToken);

        if (!$success) {
            throw new BadRequestHttpException('Invalid email verification token.');
        }

        return new ApiResponse(true);
    }

    /**
     * Delete an user.
     * Should be run by logged user or admin.
     *
     * @param string $username
     *
     * @return ApiResponse
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

        return new ApiResponse(true);
    }

    /**
     * @return ApiResponse
     */
    public function countUsers()
    {
        return new ApiResponse($this->api->countUsers());
    }

    /**
     * Returns authenticated user.
     *
     * @return ApiResponse
     *
     * @throws HttpException if no logged user.
     */
    public function authMe()
    {
        $this->mustBeLogged();

        return new ApiResponse($this->loggedUser);
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
