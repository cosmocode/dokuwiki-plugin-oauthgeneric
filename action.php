<?php

use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauthgeneric\DotAccess;
use dokuwiki\plugin\oauthgeneric\Generic;

/**
 * Service Implementation for oAuth Doorkeeper authentication
 */
class action_plugin_oauthgeneric extends Adapter
{

    /** @inheritdoc */
    public function registerServiceClass()
    {
        return Generic::class;
    }

    /** * @inheritDoc */
    public function getUser()
    {
        $oauth = $this->getOAuthService();
        $data = array();

        $url = $this->getConf('userurl');
        $raw = $oauth->request($url);

        if (!$raw) throw new OAuthException('Failed to fetch data from userurl');
        $result = json_decode($raw, true);
        if (!$result) throw new OAuthException('Failed to parse data from userurl');

        $grpdots = sexplode('[]', $this->getConf('json-grps'), 2);
        $user = DotAccess::get($result, $this->getConf('json-user'), '');
        $name = DotAccess::get($result, $this->getConf('json-name'), '');
        $mail = DotAccess::get($result, $this->getConf('json-mail'), '');
        $grps = DotAccess::get($result, $grpdots[0], []);

        // use dot notation on each group
        if (is_array($grps) && $grpdots[1]) {
            $grps = array_map(function ($grp) use ($grpdots) {
                return DotAccess::get($grp, $grpdots[1], '');
            }, $grps);
        }

        // type fixes
        if (is_array($user)) $user = array_shift($user);
        if (is_array($name)) $name = array_shift($name);
        if (is_array($mail)) $mail = array_shift($mail);
        if (!is_array($grps)) {
            $grps = explode(',', $grps);
            $grps = array_map('trim', $grps);
        }

        // fallbacks for user name
        if (empty($user)) {
            if (!empty($name)) {
                $user = $name;
            } elseif (!empty($mail)) {
                list($user) = explode('@', $mail);
            }
        }

        // fallback for full name
        if (empty($name)) {
            $name = $user;
        }

        return compact('user', 'name', 'mail', 'grps');
    }

    /** @inheritdoc */
    public function logout()
    {
        $url = $this->getConf('logouturl');
        if (!$url) {
            parent::logout();
            return;
        }

        // add ID token if available
        $oauth = $this->getOAuthService();
        $token = $oauth->getStorage()->retrieveAccessToken($oauth->service());
        $params = $token->getExtraParams();
        if (isset($params['id_token'])) {
            $url .= (strpos($url, '?') === false ? '?' : '&') . 'id_token_hint=' . urlencode($params['id_token']);
        }

        // redirect back to dokuwiki after logout
        /** @var helper_plugin_oauth $helper */
        $helper = plugin_load('helper', 'oauth');
        $redir = $helper->redirectURI();
        $url .= (strpos($url, '?') === false ? '?' : '&') . 'post_logout_redirect_uri=' . urlencode($redir);

        // add state if needed (we don't check it, but some providers require it)
        if ($this->getConf('needs-state')) {
            $state = bin2hex(random_bytes(16));
            $url .= (strpos($url, '?') === false ? '?' : '&') . 'state=' . urlencode($state);
        }

        parent::logout();
        send_redirect($url);
        exit;
    }


    /** @inheritdoc */
    public function getScopes()
    {
        return $this->getConf('scopes');
    }

    /** @inheritDoc */
    public function getLabel()
    {
        return $this->getConf('label');
    }

    /** @inheritDoc */
    public function getColor()
    {
        return $this->getConf('color');
    }
}
