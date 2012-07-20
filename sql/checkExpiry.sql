CREATE OR REPLACE FUNCTION expirycheck(notbefore timestamp, notafter timestamp, grabtime timestamp)
RETURNS boolean AS
$$
BEGIN
IF (notafter IS NULL) THEN
  RETURN TRUE;
ELSIF ( extract('epoch' FROM notbefore) >= 0 AND extract('epoch' FROM notafter) >= 0 ) THEN 
  IF ( extract('epoch' FROM notafter) <= extract('epoch' FROM notbefore) ) THEN
    RETURN TRUE;
  ELSIF ( extract('epoch' FROM notafter) < extract('epoch' FROM grabtime) ) THEN
    RETURN TRUE;
  END IF;
ELSIF ( extract('epoch' FROM notbefore) <= 0 AND extract('epoch' FROM notafter) >= 0 ) THEN 
  IF ( extract('epoch' FROM notafter) = extract('epoch' FROM notbefore) ) THEN
    RETURN TRUE;
  ELSIF ( extract('epoch' FROM notafter) < extract('epoch' FROM grabtime) ) THEN
    RETURN TRUE;
  END IF;
ELSIF ( extract('epoch' FROM notafter) <= 0 ) THEN                                          
  RETURN TRUE;
END IF;
END
$$
LANGUAGE plpgsql;
