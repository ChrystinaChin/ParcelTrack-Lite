<?php
declare(strict_types=1);
function page_admin(): void {
    login_required(['admin']);
    $summary=api_request('GET','/admin/dashboard');
    $parcels=api_request('GET','/admin/parcels');
    $riders=api_request('GET','/auth/riders');
    render_header('Admin dashboard');
    echo '<div class="pagehead"><div><p class="eyebrow">ADMIN · MEMBER 3</p><h1>Operations dashboard</h1></div></div>';
    if ($summary['status']===200) {
        echo '<div class="stats">';foreach ($summary['data']['counts'] as $status=>$count) {
            echo '<div class="stat"><span>'.h($status).'</span><strong>'.h($count).'</strong></div>'; }
        echo '</div>';
    }
    echo '<section class="panel"><h2>All parcels · Assign riders</h2>';
    if ($parcels['status']===200) {
        parcel_table($parcels['data']['parcels']??[],true);
        echo '<h3>Assign or reassign a parcel</h3>';
        post_form_start('parcel-assign','form-grid');
        field('Parcel ID','parcel_id','number','',true,'min="1" step="1"');
        echo '<label class="field">Active rider<select name="rider_id" required><option value="">Choose a rider</option>';
        foreach ($riders['data']['riders']??[] as $r) if ($r['is_active']) echo '<option value="'.h($r['id']).'">'.h($r['name']).' (#'.h($r['id']).')</option>';
        echo '</select></label><button class="btn" type="submit">Assign parcel</button></form>';
    } else echo '<p>'.h(problem($parcels)).'</p>';
    echo '</section>';render_footer();
}
function page_rider(): void {
    login_required(['rider']);$res=api_request('GET','/rider/parcels');render_header('My deliveries');
    echo '<div class="pagehead"><div><p class="eyebrow">RIDER · MEMBER 3</p><h1>Assigned deliveries</h1></div></div>';
    if ($res['status']===200) {
        echo '<section class="panel">';parcel_table($res['data']['parcels']??[]);echo '</section>';
        foreach ($res['data']['parcels'] as $p) {
            if (!in_array($p['status'],['Assigned','Out for Delivery'],true)) continue;
            echo '<section class="panel delivery"><h3 class="mono">'.h($p['tracking_number']).'</h3><p>'.h($p['recipient_address']).'</p>';
            echo '<form method="post" enctype="multipart/form-data" class="stack">';csrf_field();
            echo '<input type="hidden" name="action" value="status-update"><input type="hidden" name="parcel_id" value="'.h($p['id']).'">';
            echo '<label class="field">New status<select name="status" required>';
            if ($p['status']==='Assigned') echo '<option value="Out for Delivery">Out for Delivery</option>';
            if ($p['status']==='Out for Delivery') echo '<option value="Delivered">Delivered</option><option value="Failed">Failed</option>';
            echo '</select></label><label class="field">Proof photo (required for Delivered/Failed; JPG or PNG, max 3 MB)<input type="file" name="proof" accept=".jpg,.jpeg,.png,image/jpeg,image/png"></label>';
            echo '<button class="btn" type="submit">Update delivery</button></form></section>';
        }
    } else echo '<div class="alert alert-error">'.h(problem($res)).'</div>';
    render_footer();
}
