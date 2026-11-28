<?php
declare(strict_types=1);
function page_login(): void {
    render_header('Sign in');
    echo '<div class="authwrap"><section class="panel"><p class="eyebrow">ACCOUNT ACCESS</p><h1>Welcome back</h1><p class="muted">Seller, rider and admin access.</p>';
    post_form_start('login','stack');
    field('Email address','email','email','',true,'maxlength="254" autocomplete="username"');
    field('Password','password','password','',true,'minlength="10" maxlength="128" autocomplete="current-password"');
    echo '<button class="btn" type="submit">Sign in</button></form><p class="small">New seller? <a href="'.h(url_for('register')).'">Create an account</a></p></section></div>';
    render_footer();
}
function page_register(): void {
    render_header('Seller sign up');
    echo '<div class="authwrap"><section class="panel"><p class="eyebrow">NEW SELLER</p><h1>Create an account</h1>';
    post_form_start('register','stack');
    field('Full name','name','text','',true,'minlength="2" maxlength="100"');
    field('Email','email','email','',true,'maxlength="254"');
    field('Password (at least 12 characters)','password','password','',true,'minlength="12" maxlength="128" autocomplete="new-password"');
    echo '<button class="btn" type="submit">Register</button></form></section></div>';
    render_footer();
}
function page_password(): void {
    login_required(['seller','rider','admin']); render_header('Change password');
    echo '<div class="authwrap"><section class="panel"><h1>Change password</h1>';
    post_form_start('change-password','stack');
    field('Current password','current_password','password','',true,'autocomplete="current-password"');
    field('New password (at least 12 characters)','new_password','password','',true,'minlength="12" maxlength="128" autocomplete="new-password"');
    echo '<button class="btn" type="submit">Update password</button></form></section></div>';
    render_footer();
}
function page_riders(): void {
    login_required(['admin']); $res=api_request('GET','/auth/riders'); render_header('Rider accounts');
    echo '<div class="pagehead"><div><p class="eyebrow">ADMIN · MEMBER 1</p><h1>Rider accounts</h1></div></div>';
    echo '<section class="panel"><h2>Create rider</h2>'; post_form_start('rider-create','form-grid');
    field('Full name','name','text','',true,'maxlength="100"');
    field('Email','email','email','',true,'maxlength="254"');
    field('Temporary password (min. 12 characters)','password','password','',true,'minlength="12" maxlength="128"');
    echo '<button class="btn" type="submit">Create rider</button></form></section>';
    echo '<section class="panel"><h2>Existing riders</h2><div class="table-scroll"><table><thead><tr><th>Name</th><th>Email</th><th>Account</th><th>Action</th></tr></thead><tbody>';
    foreach ($res['data']['riders']??[] as $r) {
        echo '<tr><td>'.h($r['name']).'</td><td>'.h($r['email']).'</td><td>'.($r['is_active']?'Active':'Disabled').'</td><td>';
        if ($r['is_active']) { post_form_start('rider-disable','inline');
            echo '<input type="hidden" name="rider_id" value="'.h($r['id']).'"><button class="btn btn-light" type="submit">Disable</button></form>'; }
        echo '</td></tr>';
    }
    echo '</tbody></table></div></section>'; render_footer();
}
