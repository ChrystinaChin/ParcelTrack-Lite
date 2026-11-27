<?php
declare(strict_types=1);
function show_status(string $status): string { return '<span class="chip">'.h($status).'</span>'; }
function page_track(): void {
    $q=trim((string)($_GET['q'] ?? ''));
    $response=null;
    if ($q!=='') $response=api_request('GET','/public/track/'.rawurlencode($q));
    render_header('Track parcel');
    echo '<div class="hero"><p class="eyebrow">PARCEL TRACKING</p><h1>Know where your parcel is.</h1><p>Enter the tracking number supplied by your seller.</p></div>';
    echo '<section class="panel trackbox"><form method="get" class="trackform"><input type="hidden" name="page" value="track">';
    echo '<label class="field">Tracking number<input name="q" value="'.h($q).'" required maxlength="60" placeholder="PT-XXXXXXXXXXXXXXXXXXXXXXXX"></label>';
    echo '<button class="btn" type="submit">Track</button></form>';
    if ($response!==null) {
        if ($response['status']===200) {
            echo '<h2>Status history</h2><ol class="timeline">';
            foreach ($response['data']['history']??[] as $row) echo '<li><strong>'.h($row['status']).'</strong><time>'.h($row['created_at']).' UTC</time></li>';
            echo '</ol>';
        } else echo '<div class="alert alert-error">'.h(problem($response)).'</div>';
    }
    echo '</section>';render_footer();
}
function page_new_parcel(): void {
    login_required(['seller']); render_header('Register parcel');
    echo '<div class="pagehead"><div><p class="eyebrow">SELLER</p><h1>Register a parcel</h1></div></div>';
    echo '<section class="panel"><p class="muted">Only you and authorized delivery staff can view personal recipient details.</p>';
    post_form_start('parcel-create','stack');
    field('Recipient full name','recipient_name','text','',true,'maxlength="100"');
    field('Recipient phone','recipient_phone','tel','',true,'maxlength="20"');
    echo '<label class="field">Delivery address<textarea name="recipient_address" required minlength="5" maxlength="250" rows="3"></textarea></label>';
    field('Weight (kg)','weight_kg','text','',true,'placeholder="1.250" inputmode="decimal"');
    echo '<button class="btn" type="submit">Register parcel</button></form></section>'; render_footer();
}
function parcel_table(array $records, bool $withRider=false): void {
    echo '<div class="table-scroll"><table><thead><tr><th>Tracking number</th><th>Recipient</th><th>Status</th>'.($withRider?'<th>Rider ID</th>':'').'<th>Details</th></tr></thead><tbody>';
    foreach ($records as $p) {
        echo '<tr><td class="mono">'.h($p['tracking_number']).'</td><td>'.h($p['recipient_name']).'</td><td>'.show_status((string)$p['status']).'</td>';
        if ($withRider) echo '<td>'.h($p['rider_id']??'Unassigned').'</td>';
        echo '<td><a href="'.h(url_for('parcel',['id'=>$p['id']])).'">View</a></td></tr>';
    }
    if (!$records) echo '<tr><td colspan="5" class="muted">No parcels available.</td></tr>';
    echo '</tbody></table></div>';
}
function page_seller(): void {
    login_required(['seller']); $search=trim((string)($_GET['search']??''));
    $res=api_request('GET','/parcels?search='.rawurlencode($search));
    render_header('My parcels');
    echo '<div class="pagehead"><div><p class="eyebrow">SELLER</p><h1>My parcels</h1></div><a class="btn" href="'.h(url_for('new-parcel')).'">+ New parcel</a></div>';
    echo '<section class="panel"><form method="get" class="search"><input type="hidden" name="page" value="seller"><input name="search" maxlength="100" placeholder="Search tracking number" value="'.h($search).'"><button class="btn" type="submit">Search</button></form>';
    if ($res['status']===200) parcel_table($res['data']['parcels']??[]); else echo '<p>'.h(problem($res)).'</p>';
    echo '</section>'; render_footer();
}
function page_parcel(): void {
    login_required(['seller','rider','admin']); $id=filter_var($_GET['id']??null,FILTER_VALIDATE_INT);
    if (!$id || $id<1) { http_response_code(404);render_header('Parcel not found');echo '<p>Parcel not found.</p>';render_footer();return; }
    $res=api_request('GET','/parcels/'.$id);
    if ($res['status']!==200) { http_response_code($res['status']); render_header('Parcel unavailable');echo '<section class="panel"><h1>'.h(problem($res)).'</h1></section>';render_footer();return; }
    $p=$res['data']['parcel'];
    render_header('Parcel details');
    echo '<div class="pagehead"><div><p class="eyebrow">PARCEL DETAILS</p><h1 class="mono">'.h($p['tracking_number']).'</h1></div>'.show_status($p['status']).'</div>';
    echo '<div class="columns"><section class="panel"><h2>Delivery information</h2><dl class="details">';
    foreach (['Recipient'=>$p['recipient_name'],'Phone'=>$p['recipient_phone'],'Address'=>$p['recipient_address'],
              'Weight (kg)'=>number_format((int)$p['weight_grams']/1000,3),
              'Assigned rider'=>($p['rider_id']??'Not assigned')] as $title=>$value) {
        echo '<dt>'.h($title).'</dt><dd>'.h($value).'</dd>';
    }
    echo '</dl>';
    if ($res['data']['has_proof']??false) echo '<p><a href="'.h(url_for('proof',['id'=>$id])).'">Download proof photo</a></p>';
    echo '</section><section class="panel"><h2>Status history</h2><ol class="timeline">';
    foreach ($res['data']['history']??[] as $row) echo '<li><strong>'.h($row['status']).'</strong><time>'.h($row['created_at']).' UTC</time></li>';
    echo '</ol></section></div>';render_footer();
}
