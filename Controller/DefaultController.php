<?php

namespace EsiaBundle\Controller;

use Application\Sonata\UserBundle\Entity\User;
use FOS\OAuthServerBundle\Security\Authentication\Token\OAuthToken;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;


/**
 * Class DefaultController
 * @package EsiaBundle\Controller
 */
class DefaultController extends Controller
{
    /**
     * Login PAGE
     *
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function loginAction(Request $request)
    {
        $config = array_filter($this->container->getParameter('esia'));
        $esia = new \esia\OpenId($config);
        $uri = $esia->getUrl();

        return $this->redirect($uri);
    }


    /**
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     * @throws \esia\exceptions\SignFailException
     */
    public function endpointAction(Request $request)
    {
        $code = $request->get('code');
        $config = array_filter($this->container->getParameter('esia'));
        $esia = new \esia\OpenId($config);

        $esia->getToken($code);

        $personInfo = json_decode(json_encode($esia->getPersonInfo()), 1);

        $contactInfo = json_decode(json_encode($esia->getContactInfo()) , 1);

        $contactInfo = array_filter($contactInfo, function($c){
           return $c['type'] == 'EML';
        });

        if (!empty($contactInfo)) {
            $contactInfo = reset($contactInfo);
        } else {
            return \Exception('Не указан почтовый адрес (e-mail)');
        }

        $email = $contactInfo['value'];
        $personInfo['personEMail'] = $email;

        if (!empty($personInfo)) {
            /** @var \Doctrine\ORM\EntityManager $em */
            $em = $this->container->get('doctrine')->getManager();

            $userManager = $this->container->get('fos_user.user_manager');



            $user = $userManager->findUserByEmail($personInfo['personEMail']);
            if (empty($user)) {
                $user = new User();
                $user->setUsername($personInfo['personEMail']);
                $user->setEmail($personInfo['personEMail']);
                $user->setEnabled(1);
                $user->setLocked(0);
                $user->setFirstname($personInfo['firstName']);
                $user->setLastname($personInfo['lastName']);
                $user->setPlainPassword(md5(time()));
                $em->persist($user);
                $em->flush();
            }
            $token = new UsernamePasswordToken($user, null, "main", $user->getRoles());
            $this->get("security.context")->setToken($token);

            //now dispatch the login event
            $request = $this->get("request");
            $event = new InteractiveLoginEvent($request, $token);
            $this->get("event_dispatcher")->dispatch("security.interactive_login", $event);
        }

        $uri = $this->container->getParameter('url.portal');
        $client = $this->container->getParameter('client.portal');
        $url = "/oauth/v2/auth?client_id=$client&redirect_uri=$uri/oauth/verify&response_type=code";
        return $this->redirect($url);
    }
}
