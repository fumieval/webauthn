function getJSON(path, success)
{
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function()
  {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      if (xhr.status === 200) {
        success(JSON.parse(xhr.responseText));
      } else {
        console.log(xhr);
      }
    }
  };
  xhr.open("GET", path, true);
  xhr.send();
}

function postJSON(path, body, success)
{
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function()
  {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      if (xhr.status === 200) {
        success(JSON.parse(xhr.responseText));
      } else {
        console.log(xhr);
      }
    }
  };
  xhr.open("POST", path, true);
  xhr.send(body);
}
