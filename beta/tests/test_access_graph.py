from eda import access_graph


def test_path_resolves_through_group_permission_set_and_role(db):
    path = access_graph.resolve_path(db, "derrick", "ec2:DescribeInstances", "ec2-prod-1")
    assert path is not None
    relations = [hop["relation"] for hop in path.hops]
    assert relations == ["member_of", "assigned", "can_assume", "role_allows", "account_contains"]
    assert path.permits("ec2:DescribeInstances")  # via ec2:Describe* wildcard


def test_no_path_for_contractor_without_edges(db):
    assert access_graph.resolve_path(db, "eve", "ec2:DescribeInstances", "ec2-prod-1") is None


def test_path_does_not_confer_unrelated_action(db):
    assert access_graph.resolve_path(db, "derrick", "s3:GetObject", "ec2-prod-1") is None


def test_alternate_path_found_when_first_lacks_action(db):
    # rotate authority comes via prod-secops, not the read-only auditor path
    path = access_graph.resolve_path(db, "derrick", "secretsmanager:RotateSecret", "db-creds-prod")
    assert path is not None
    assert any("prod-secops" in hop["dst"] for hop in path.hops)
