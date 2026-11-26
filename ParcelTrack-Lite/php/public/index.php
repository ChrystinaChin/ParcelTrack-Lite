<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/bootstrap.php';
require dirname(__DIR__).'/src/m1_pages.php';
require dirname(__DIR__).'/src/m2_pages.php';
require dirname(__DIR__).'/src/m3_pages.php';

// Session role is only a UI convenience: the Python API independently checks
// the authenticated database role and resource ownership on EVERY request.
if (isset($_SESSION['token'])) {
    $verified=api_request('GET','/auth/me');
    if ($verified['status']===401 || $verified['status']===403) {
        unset($_SESSION['token'],$_SESSION['role']);
        flash('Please sign in again.','error');
    } elseif ($verified['status']===200) {
        $_SESSION['role']=$verified['data']['user']['role'];
    }
}

if ($_SERVER['REQUEST_METHOD']==='POST') {
    require_csrf();
    $action = (string)($_POST['action']??'');
    $page='track'; $params=[];
    switch ($action) {
        case 'register':
            $res=api_request('POST','/auth/register',[
                'name'=>(string)($_POST['name']??''),'email'=>(string)($_POST['email']??''),
                'password'=>(string)($_POST['password']??'')]);
            $page=$res['status']===201?'login':'register'; break;
        case 'login':
            $res=api_request('POST','/auth/login',[
                'email'=>(string)($_POST['email']??''),'password'=>(string)($_POST['password']??'')]);
            if ($res['status']===200 && isset($res['data']['token'])) {
                session_regenerate_id(true);
                $_SESSION['csrf']=bin2hex(random_bytes(32));
                $_SESSION['token']=$res['data']['token'];
                $_SESSION['role']=$res['data']['user']['role'];
                $page=match(role()){'seller'=>'seller','rider'=>'rider','admin'=>'admin',default=>'track'};
            } else $page='login';
            break;
        case 'logout':
            if (isset($_SESSION['token'])) api_request('POST','/auth/logout');
            $_SESSION=[];session_regenerate_id(true);
            $_SESSION['csrf']=bin2hex(random_bytes(32));
            flash('Signed out successfully.');redirect_page('login');
        case 'change-password':
            login_required(['seller','rider','admin']);
            $res=api_request('POST','/auth/change-password',[
                'current_password'=>(string)($_POST['current_password']??''),
                'new_password'=>(string)($_POST['new_password']??'')]);
            $page=$res['status']===200?'login':'password';
            if ($res['status']===200) {
                unset($_SESSION['token'],$_SESSION['role']);session_regenerate_id(true);
                $_SESSION['csrf']=bin2hex(random_bytes(32));
            }
            break;
        case 'rider-create':
            login_required(['admin']);
            $res=api_request('POST','/auth/riders',[
                'name'=>(string)($_POST['name']??''),'email'=>(string)($_POST['email']??''),
                'password'=>(string)($_POST['password']??'')]);$page='riders';break;
        case 'rider-disable':
            login_required(['admin']);$id=filter_var($_POST['rider_id']??null,FILTER_VALIDATE_INT);
            $res=$id?api_request('POST','/auth/riders/'.$id.'/disable'):
                     ['status'=>400,'data'=>['detail'=>'Invalid rider ID.']];
            $page='riders';break;
        case 'parcel-create':
            login_required(['seller']);
            $res=api_request('POST','/parcels',[
                'recipient_name'=>(string)($_POST['recipient_name']??''),
                'recipient_phone'=>(string)($_POST['recipient_phone']??''),
                'recipient_address'=>(string)($_POST['recipient_address']??''),
                'weight_kg'=>(string)($_POST['weight_kg']??'')]);
            $page=$res['status']===201?'seller':'new-parcel';
            if ($res['status']===201) $res['data']['message'] .= ' Tracking: '.$res['data']['tracking_number'];
            break;
        case 'parcel-assign':
            login_required(['admin']);$id=filter_var($_POST['parcel_id']??null,FILTER_VALIDATE_INT);
            $rider=filter_var($_POST['rider_id']??null,FILTER_VALIDATE_INT);
            $res=($id && $rider)?api_request('POST','/admin/parcels/'.$id.'/assign',['rider_id'=>$rider]):
                  ['status'=>400,'data'=>['detail'=>'Valid parcel and rider IDs required.']];
            $page='admin';break;
        case 'status-update':
            login_required(['rider']);$id=filter_var($_POST['parcel_id']??null,FILTER_VALIDATE_INT);
            $file=$_FILES['proof']??null;
            if ($file && $file['error']===UPLOAD_ERR_NO_FILE) $file=null;
            if ($file && ($file['error']!==UPLOAD_ERR_OK || $file['size']>3*1024*1024 ||
                          !is_uploaded_file($file['tmp_name']) ||
                          !preg_match('/\A[A-Za-z0-9_-]{1,64}\.(?:jpe?g|png)\z/i',(string)$file['name']))) {
                $res=['status'=>400,'data'=>['detail'=>'Invalid photo upload (max 3 MB).']];
            } elseif (!$id) $res=['status'=>400,'data'=>['detail'=>'Invalid parcel ID.']];
            else $res=api_request('POST','/rider/parcels/'.$id.'/status',
                      ['status'=>(string)($_POST['status']??'')],$file ?? []);
            $page='rider';break;
        default:
            http_response_code(400);exit('Unknown form action.');
    }
    $successful=($res['status']>=200 && $res['status']<300);
    flash($successful?($res['data']['message']??'Saved.') : problem($res),$successful?'notice':'error');
    redirect_page($page,$params);
}

// The photo action is authenticated. Files never live under php/public.
$page=(string)($_GET['page']??'track');
if ($page==='proof') {
    login_required(['seller','rider','admin']);
    $id=filter_var($_GET['id']??null,FILTER_VALIDATE_INT);
    if (!$id) { http_response_code(404);exit('Not found.'); }
    $res=api_request('GET','/parcels/'.$id.'/proof',null,null,true);
    if ($res['status']!==200) { http_response_code($res['status']);exit('File not available.'); }
    header('Content-Type: application/octet-stream');
    $extension=str_starts_with($res['data'],"\x89PNG\r\n\x1a\n") ? '.png' : '.jpg';
    header('Content-Disposition: attachment; filename="delivery-proof'.$extension.'"');
    header('Content-Length: '.strlen($res['data']));echo $res['data'];exit;
}
switch ($page) {
    case 'login':page_login();break;
    case 'register':page_register();break;
    case 'password':page_password();break;
    case 'riders':page_riders();break;
    case 'track':page_track();break;
    case 'new-parcel':page_new_parcel();break;
    case 'seller':page_seller();break;
    case 'parcel':page_parcel();break;
    case 'admin':page_admin();break;
    case 'rider':page_rider();break;
    default:http_response_code(404);render_header('Not found');echo '<h1>Page not found</h1>';render_footer();
}
