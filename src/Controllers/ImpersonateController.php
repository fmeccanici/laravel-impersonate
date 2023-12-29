<?php

namespace Lab404\Impersonate\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Lab404\Impersonate\Services\ImpersonateManager;

class ImpersonateController extends Controller
{
    /** @var ImpersonateManager */
    protected $manager;

    /**
     * ImpersonateController constructor.
     */
    public function __construct()
    {
        $this->manager = app()->make(ImpersonateManager::class);
        
        $guard = $this->manager->getDefaultSessionGuard();
        $this->middleware('auth:' . $guard)->only('take');
    }

    /**
     * @param int         $id
     * @param string|null $guardName
     * @return  RedirectResponse
     * @throws  \Exception
     */
    public function take(Request $request, $id, $guardName = null)
    {
        $guardName = $guardName ?? $this->manager->getDefaultSessionGuard();

        // Cannot impersonate yourself
        if ($id == $request->user()->getAuthIdentifier() && ($this->manager->getCurrentAuthGuardName() == $guardName)) {
            dd('cannot impersonate yourself');
            abort(403);
        }

        // Cannot impersonate again if you're already impersonate a user
        if ($this->manager->isImpersonating()) {
            dd('cannot impersonate again');
            abort(403);
        }

        if (!$request->user()->canImpersonate()) {
            dd('user cannot impersonate');
            abort(403);
        }

        $userToImpersonate = $this->manager->findUserById($id, $guardName);

        $leaveRedirectUrl = $request->get('leaveRedirectTo');

        if ($userToImpersonate->canBeImpersonated()) {
            if ($this->manager->take($request->user(), $userToImpersonate, $guardName, $leaveRedirectUrl)) {
                $takeRedirect = $this->manager->getTakeRedirectTo();
                if ($takeRedirect !== 'back') {
                    return redirect()->to($takeRedirect);
                }
            }
        }

        return redirect()->back();
    }

    /**
     * @return RedirectResponse
     */
    public function leave()
    {
        if (!$this->manager->isImpersonating()) {
            dd('not impersonating');
            abort(403);
        }

        $leaveRedirect = $this->manager->getLeaveRedirectTo();

        $this->manager->leave();

        if ($leaveRedirect !== 'back') {
            return redirect()->to($leaveRedirect);
        }
        return redirect()->back();
    }
}
