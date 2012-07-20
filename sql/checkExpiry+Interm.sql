CREATE OR REPLACE FUNCTION expirycheckinterm(v_notbefore timestamp, v_notafter timestamp, v_grabtime timestamp, v_certno int, scantype varchar, v_prefix varchar, v_suffix varchar)
RETURNS boolean AS
$$
DECLARE
   query varchar;
   v_icerttable varchar;
   v_icertrow RECORD;
BEGIN
IF expirycheck(v_notbefore, v_notafter, v_grabtime) THEN
   RETURN TRUE;
END IF;
IF scantype = 'tum' THEN
    v_icerttable := 'icertificates_' || v_suffix;
ELSIF scantype = 'world' OR scantype = 'eff' THEN
    v_icerttable := v_prefix || '_icerts_' || v_suffix;
ELSE
   RAISE EXCEPTION 'WRONG SCANTYPE!';
END IF;
query := 'SELECT notbefore, notafter FROM ' || v_icerttable || ' WHERE certrefer = ' || v_certno;
FOR v_icertrow IN 
EXECUTE query
LOOP
    IF expirycheck(v_icertrow.notbefore, v_icertrow.notafter, v_grabtime) THEN
       RETURN TRUE;
    END IF;
END LOOP;
RETURN FALSE;
END;
$$
LANGUAGE plpgsql;
